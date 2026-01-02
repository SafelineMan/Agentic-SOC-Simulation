import requests
import json
import os
from dotenv import load_dotenv
from openai import OpenAI
from .ocsf import OCSFEvent
from .engine import DetectionEngine, DetectionRule

# Load environment variables
load_dotenv()

class BaseAgent:
    def __init__(self, name, mcp_url="http://localhost:8000", api_key=None, vt_api_key=None):
        self.name = name
        self.mcp_url = mcp_url
        self.vt_api_key = vt_api_key or os.getenv("VIRUSTOTAL_API_KEY")
        
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        
        if self.api_key:
            self.client = OpenAI(
                api_key=self.api_key,
                base_url="https://api.deepseek.com"
            )
        else:
            self.client = None

    def log(self, message, callback=None):
        entry = f"[{self.name}] {message}"
        print(entry)
        if callback:
            callback(entry)
        return entry

    def get_tools(self, tool_names):
        """Fetches specific tools from MCP server."""
        try:
            response = requests.get(f"{self.mcp_url}/tools")
            if response.status_code == 200:
                all_tools = response.json()
                filtered = [t for t in all_tools if t['name'] in tool_names]
                formatted = []
                for t in filtered:
                    formatted.append({
                        "type": "function",
                        "function": {
                            "name": t["name"],
                            "description": t["description"],
                            "parameters": t["parameters"]
                        }
                    })
                return formatted
        except Exception as e:
            print(f"Error fetching tools: {e}")
            return []
        return []

    def call_tool(self, tool_name, arguments):
        try:
            # Inject VT key if available and relevant
            if tool_name == "check_ip_reputation" and self.vt_api_key:
                arguments["api_key"] = self.vt_api_key

            response = requests.post(
                f"{self.mcp_url}/execute",
                json={"tool_name": tool_name, "arguments": arguments}
            )
            if response.status_code == 200:
                return response.json()['result']
            else:
                return f"Error: {response.text}"
        except Exception as e:
            return f"Connection Error: {str(e)}"

    def run_loop(self, system_prompt, user_input, tools, callback, max_turns=5):
        if not self.client:
            return "Error: API Key not configured."

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_input}
        ]
        
        final_content = ""
        
        for _ in range(max_turns):
            try:
                response = self.client.chat.completions.create(
                    model="deepseek-chat",
                    messages=messages,
                    tools=tools if tools else None,
                    stream=False
                )
                message = response.choices[0].message
                messages.append(message)
                
                if message.content:
                    self.log(f"{message.content}", callback)
                    final_content += message.content + "\n"

                if message.tool_calls:
                    for tool_call in message.tool_calls:
                        func_name = tool_call.function.name
                        func_args = json.loads(tool_call.function.arguments)
                        self.log(f"调用工具 `{func_name}` 参数: {func_args}", callback)
                        
                        result = self.call_tool(func_name, func_args)
                        self.log(f"工具返回: {result}", callback)
                        
                        # Special handling for approval
                        if str(result).startswith("PENDING_APPROVAL"):
                             # Avoid double prefixing if the tool already returned the prefix
                             return result

                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": str(result)
                        })
                else:
                    return final_content
            except Exception as e:
                self.log(f"Error: {e}", callback)
                return str(e)
        return final_content

class TriageAgent(BaseAgent):
    def analyze(self, alert_data, callback):
        self.log("正在分析告警可信度...", callback)
        prompt = """你是一个 SOC 分诊员 (Triage Analyst)。
你的任务是分析安全告警，判断它是误报 (False Positive) 还是值得调查的可疑事件。
请分析 IP、Payload 和攻击类型。
如果是误报，请说明理由。
如果是可疑事件，请简要说明风险点。
只输出分析结果，不要调用工具。"""
        return self.run_loop(prompt, f"告警数据: {json.dumps(alert_data)}", [], callback, max_turns=1)

class ForensicAgent(BaseAgent):
    def investigate(self, alert_data, triage_notes, callback):
        self.log("正在进行取证调查...", callback)
        tools = self.get_tools(["check_ip_reputation", "analyze_payload", "graph_add_entity", "graph_add_relation", "graph_query"])
        
        prompt = """你是一个 SOC 取证专家 (Forensic Investigator)。
你的任务是深入调查可疑告警。
1. 使用 `check_ip_reputation` 检查 IP。
2. 使用 `analyze_payload` 分析攻击载荷。
3. **构建高连通性图谱（核心任务）：**
   - **优先使用 `graph_add_relation`**：不要单独调用 `graph_add_entity`，除非该实体完全孤立。`graph_add_relation` 会自动创建节点。
   - **必填关系**：
     - 攻击源 -> 攻击目标：使用 `analyze_payload` 的结果作为关系名称（例如：`IP:1.2.3.4` --[SQL Injection]--> `Host:Web-Server`）。
     - 归属关系：`User` --[owns]--> `Host`。
     - 交互关系：`Process` --[spawns]--> `Process`。
   - **拒绝孤立节点**：确保图谱中没有孤立的点，所有实体都必须通过边连接。
4. 总结你的发现。
请使用中文。"""
        return self.run_loop(prompt, f"告警数据: {json.dumps(alert_data)}\n分诊意见: {triage_notes}", tools, callback, max_turns=8)

class CommanderAgent(BaseAgent):
    def decide(self, alert_data, forensic_report, callback):
        self.log("正在制定响应决策...", callback)
        tools = self.get_tools(["firewall_block_ip", "ask_human_approval"])
        
        prompt = """你是一个 SOC 指挥官 (Commander)。
根据取证报告，决定是否采取行动。

**决策逻辑：**
1. 如果威胁非常明确且紧急（如 C2 通信、横向移动），请优先使用 `firewall_block_ip` 进行自动遏制。
2. **强制人工审批场景**：
   - 如果涉及关键资产（如数据库、域控）。
   - 如果需要进行高风险操作（如隔离主机、重置全域密码）。
   - 如果你不确定是否应该封禁。
   - **为了演示目的，请尽量在处理高危告警时触发一次 `ask_human_approval`。**

最后输出最终报告。
请使用中文。"""
        return self.run_loop(prompt, f"告警数据: {json.dumps(alert_data)}\n取证报告: {forensic_report}", tools, callback, max_turns=5)

class ReporterAgent(BaseAgent):
    def report(self, case_context, callback):
        self.log("正在生成最终案件调查报告...", callback)
        
        prompt = """你是一个 SOC 报告员 (Reporter)。
你的任务是根据整个案件的调查过程（可能包含多个关联告警），撰写一份结构化的《安全事件调查报告》。
报告应包含以下部分：
1. **案件摘要**：简要描述整个攻击链（如：钓鱼 -> C2 -> 横向移动 -> 数据外泄）。
2. **攻击时间线**：按时间顺序列出关键事件。
3. **调查发现**：列出关键证据（IP、Payload、关联实体、受影响资产）。
4. **处置结果**：采取了什么行动（如封禁、隔离）。
5. **改进建议**：针对此类 APT 攻击的防御建议。

请使用 Markdown 格式，语言专业、简洁。"""
        
        context = f"案件调查记录:\n{json.dumps(case_context, indent=2, ensure_ascii=False)}"
        return self.run_loop(prompt, context, [], callback, max_turns=1)

class PurpleTeamAgent(BaseAgent):
    def generate_telemetry(self, scenario_description, callback):
        self.log("正在生成 OCSF 遥测数据 (包含正常背景噪声)...", callback)
        
        prompt = """你是一个紫队工程师 (Purple Team Engineer)。
你的任务是根据攻击剧本，生成符合 OCSF (Open Cybersecurity Schema Framework) 标准的原始遥测日志。

**要求：**
1. **混合数据**：生成 15-20 条日志。其中 3-5 条是剧本描述的恶意攻击行为，其余必须是该用户的**正常日常行为**（如浏览网页、后台服务、文件操作），以模拟真实的噪音环境。
2. **时间连续性**：日志的时间戳必须是连续的，攻击行为要混杂在正常行为中间。
3. **格式严格**：必须返回一个 JSON 列表，每个元素是一个 OCSF Event 对象。

**OCSF 关键字段参考：**
- class_uid: 1007 (Process Activity), 4001 (Network Activity), 1001 (File Activity)
- activity_id: 1 (Create/Connect), 2 (Read/Listen)
- src_endpoint: {ip, hostname}
- process: {name, cmd_line, user} (Ensure cmd_line is populated for suspicious processes)

**输出格式：**
只输出 JSON 列表，不要包含 Markdown 标记。
"""
        if not self.client:
            return []

        try:
            response = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": f"攻击剧本: {scenario_description}"}
                ],
                stream=False
            )
            content = response.choices[0].message.content
            # Clean up markdown
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            
            data = json.loads(content.strip())
            events = []
            for item in data:
                try:
                    events.append(OCSFEvent(**item))
                except Exception as e:
                    self.log(f"[Warning] Skipping invalid event: {e} | Data: {json.dumps(item)}", callback)
            
            if not events:
                self.log(f"[Error] No valid events generated. Raw content: {content[:500]}...", callback)

            self.log(f"已生成 {len(events)} 条遥测日志。", callback)
            return events
        except Exception as e:
            self.log(f"生成遥测失败: {e}", callback)
            return []

class DetectionEngineerAgent(BaseAgent):
    def develop_rules(self, telemetry_sample, scenario_description, callback):
        self.log("正在分析遥测数据并开发检测规则...", callback)
        
        prompt = """你是一个检测工程师 (Detection Engineer)。
你的任务是分析提供的 OCSF 遥测数据，找出其中的恶意行为，并编写检测规则。

**输入：**
1. 攻击剧本描述。
2. 一批 OCSF 格式的原始日志（包含噪音）。

**任务：**
1. 识别出符合剧本的恶意日志。
2. 编写 1-3 条检测规则来捕获这些行为。
3. 规则格式必须是 JSON，包含简单的匹配逻辑。

**规则逻辑格式 (Python Dict 风格):**
{
    "class_uid": 1007, 
    "conditions": {
        "process.name": "cmd.exe",
        "process.cmd_line__contains": "/c powershell"
    }
}
支持的操作符后缀: __contains, __endswith, __startswith。无后缀则为精确匹配。

**输出格式：**
返回一个 JSON 列表，包含多个规则对象。
每个规则对象包含: id, title, description, severity, logic。
只输出 JSON。
"""
        if not self.client:
            return []

        # Convert telemetry to simplified JSON for LLM to save tokens
        # Use model_dump instead of dict for Pydantic v2 compatibility if needed, but dict() works for v1
        try:
            telemetry_json = json.dumps([e.dict(exclude_none=True) for e in telemetry_sample], indent=2)
        except:
             # Fallback for Pydantic v2
             telemetry_json = json.dumps([e.model_dump(exclude_none=True) for e in telemetry_sample], indent=2)

        try:
            response = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": f"剧本: {scenario_description}\n\n遥测数据样本:\n{telemetry_json}"}
                ],
                stream=False
            )
            content = response.choices[0].message.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
                
            data = json.loads(content.strip())
            rules = []
            for item in data:
                rules.append(DetectionRule(**item))
            
            self.log(f"已开发 {len(rules)} 条检测规则。", callback)
            return rules
        except Exception as e:
            self.log(f"开发规则失败: {e}", callback)
            return []



class Agent:
    """Orchestrator Agent that manages the multi-agent workflow."""
    def __init__(self, deepseek_api_key=None, virustotal_api_key=None):
        self.triage = TriageAgent("Triage", api_key=deepseek_api_key, vt_api_key=virustotal_api_key)
        self.forensic = ForensicAgent("Forensics", api_key=deepseek_api_key, vt_api_key=virustotal_api_key)
        self.commander = CommanderAgent("Commander", api_key=deepseek_api_key, vt_api_key=virustotal_api_key)
        self.reporter = ReporterAgent("Reporter", api_key=deepseek_api_key, vt_api_key=virustotal_api_key)
        
        # New Agents
        self.purple = PurpleTeamAgent("PurpleTeam", api_key=deepseek_api_key)
        self.detection_eng = DetectionEngineerAgent("DetectionEng", api_key=deepseek_api_key)
        self.engine = DetectionEngine()
        
        self.history = []
        self.case_context = []

    def run_purple_step1_gen_data(self, scenario_text, stream_callback=None):
        """Step 1: Generate Telemetry"""
        self.history = []
        def cb(msg):
            self.history.append(msg)
            if stream_callback: stream_callback(msg)
            
        cb(f"[System] 启动紫队演练 Step 1: 生成遥测数据...")
        cb(f"[PurpleTeam] 正在解析攻击剧本: {scenario_text[:50]}...")
        cb(f"[PurpleTeam] 正在构建 OCSF 遥测数据模型 (混合正常流量与攻击流量)...")
        telemetry = self.purple.generate_telemetry(scenario_text, cb)
        cb(f"[PurpleTeam] 数据生成完毕，准备入库。")
        return telemetry

    def run_purple_step2_dev_rules(self, telemetry, scenario_text, stream_callback=None):
        """Step 2: Develop Rules"""
        self.history = []
        def cb(msg):
            self.history.append(msg)
            if stream_callback: stream_callback(msg)
            
        cb(f"[System] 启动紫队演练 Step 2: 开发检测规则...")
        cb(f"[DetectionEng] 正在从数仓读取 {len(telemetry)} 条遥测日志...")
        cb(f"[DetectionEng] 正在分析攻击特征并编写 Sigma/JSON 规则...")
        rules = self.detection_eng.develop_rules(telemetry, scenario_text, cb)
        cb(f"[DetectionEng] 规则开发完毕，准备部署。")
        return rules

    def run_purple_step3_engine_scan(self, rules, telemetry, stream_callback=None):
        """Step 3: Engine Scan"""
        self.history = []
        def cb(msg):
            self.history.append(msg)
            if stream_callback: stream_callback(msg)
            
        cb(f"[System] 启动紫队演练 Step 3: 规则引擎扫描...")
        cb(f"[Engine] 正在初始化检测引擎，加载 {len(rules)} 条新规则...")
        cb(f"[Engine] 开始回放 {len(telemetry)} 条历史遥测数据...")
        self.engine.load_rules(rules)
        alerts = self.engine.evaluate(telemetry)
        cb(f"[Engine] 扫描完成，产生 {len(alerts)} 条高危告警。")
        return alerts

    def run_purple_prep(self, scenario_text, stream_callback=None):
        """
        Runs the Purple Team & Detection Engineering phase.
        Returns a list of alerts to be processed by the SOC.
        """
        self.history = []
        def cb(msg):
            self.history.append(msg)
            if stream_callback: stream_callback(msg)

        cb(f"[System] 启动紫队演练闭环 (Purple Team Loop)...")
        
        # 1. Purple Team: Generate Telemetry
        telemetry = self.purple.generate_telemetry(scenario_text, cb)
        if not telemetry:
            cb("[System] 遥测生成失败，流程终止。")
            return [], []

        # 2. Detection Engineer: Develop Rules
        rules = self.detection_eng.develop_rules(telemetry, scenario_text, cb)
        if not rules:
            cb("[System] 规则开发失败，流程终止。")
            return [], []
            
        # 3. Engine: Load Rules & Detect
        cb(f"[Engine] 加载 {len(rules)} 条检测规则并回放遥测数据...")
        self.engine.load_rules(rules)
        alerts = self.engine.evaluate(telemetry)
        cb(f"[Engine] 产生 {len(alerts)} 条告警。")
        
        if not alerts:
            cb("[System] 未触发任何告警，演练结束 (漏报)。")
            return [], telemetry

        return alerts, telemetry

    def run_purple_loop(self, scenario_text, stream_callback=None):
        # Deprecated in favor of run_purple_prep + standard loop
        pass

    def think(self, alert_data, stream_callback=None, skip_report=False):
        self.history = []
        
        def cb(msg):
            self.history.append(msg)
            if stream_callback: stream_callback(msg)

        cb(f"[System] 启动多 Agent 协同工作流...")

        # 1. Triage Phase
        triage_result = self.triage.analyze(alert_data, cb)
        if "误报" in triage_result or "False Positive" in triage_result:
            cb("[System] 告警被判定为误报，流程结束。")
            return "Closed (False Positive)", self.history, None

        # 2. Forensic Phase
        forensic_report = self.forensic.investigate(alert_data, triage_result, cb)

        # 3. Commander Phase
        final_decision = self.commander.decide(alert_data, forensic_report, cb)
        
        # Store context for the case (Store BEFORE returning for approval)
        self.case_context.append({
            "alert": alert_data,
            "triage": triage_result,
            "forensic": forensic_report,
            "decision": final_decision
        })

        approval_request = None
        if "PENDING_APPROVAL" in final_decision:
             cb("[System] ⚠️ 收到人工审批请求。已加入待办队列，Agent 继续执行...")
             approval_request = final_decision

        # 4. Reporting Phase (Optional)
        final_report = None
        if not skip_report:
            final_report = self.reporter.report(self.case_context, cb)
        
        status = "Incident Closed"
        if approval_request:
            status = f"PENDING_APPROVAL_ASYNC: {approval_request}"
            
        return status, self.history, final_report

    def generate_case_report(self, stream_callback=None):
        """Generates a report for the accumulated case context."""
        def cb(msg):
            if stream_callback: stream_callback(msg)
            
        return self.reporter.report(self.case_context, cb)
