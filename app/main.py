import streamlit as st
import requests
import json
import time
from datetime import datetime, timedelta
import sys
import os
import html
import markdown
import networkx as nx
import matplotlib.pyplot as plt
import textwrap
from streamlit_agraph import agraph, Node, Edge, Config

# Add the root directory to sys.path to allow importing agent modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agent.core import Agent, ScenarioGenerator

st.set_page_config(page_title="ASS - 下一代自主安全运营仿真中心", layout="wide")

st.title("🛡️ Agentic SOC Simulation (ASS): 下一代自主安全运营仿真中心")

# Initialize session state
if 'agent_history' not in st.session_state:
    st.session_state['agent_history'] = []
if 'agent_status' not in st.session_state:
    st.session_state['agent_status'] = ""
if 'alert_queue' not in st.session_state:
    st.session_state['alert_queue'] = []
if 'decision_history' not in st.session_state:
    st.session_state['decision_history'] = []
if 'pending_approvals' not in st.session_state:
    st.session_state['pending_approvals'] = []
if 'simulation_running' not in st.session_state:
    st.session_state['simulation_running'] = False
if 'processed_alerts_count' not in st.session_state:
    st.session_state['processed_alerts_count'] = 0
if 'agent_instance' not in st.session_state:
    st.session_state['agent_instance'] = None
if 'active_scenario_alerts' not in st.session_state:
    st.session_state['active_scenario_alerts'] = []
if 'custom_scenario' not in st.session_state:
    st.session_state['custom_scenario'] = None

# Define APT Scenario Alerts
base_time = datetime.now() - timedelta(hours=2)

apt_alerts = [
    {
        "type": "Phishing Email Detected",
        "source_ip": "45.33.22.11",
        "target": "User-Workstation-01",
        "timestamp": (base_time).strftime("%Y-%m-%d %H:%M:%S"),
        "details": "Target IP: 10.0.0.15. Subject: 'Urgent Invoice', Attachment: 'invoice.exe'"
    },
    {
        "type": "C2 Connection Attempt",
        "source_ip": "User-Workstation-01", # Internal infected host
        "target": "185.100.200.5", # External C2
        "timestamp": (base_time + timedelta(minutes=12)).strftime("%Y-%m-%d %H:%M:%S"),
        "details": "Source IP: 10.0.0.15. Suspicious DNS query to update.microsoft-support.com"
    },
    {
        "type": "Lateral Movement (SMB Brute Force)",
        "source_ip": "User-Workstation-01",
        "target": "DB-Server-01",
        "timestamp": (base_time + timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S"),
        "details": "Source IP: 10.0.0.15, Target IP: 10.0.0.20. Failed login attempts: 500"
    },
    {
        "type": "Persistence Established",
        "source_ip": "User-Workstation-01",
        "target": "DB-Server-01",
        "timestamp": (base_time + timedelta(hours=1, minutes=5)).strftime("%Y-%m-%d %H:%M:%S"),
        "details": "Source IP: 10.0.0.15, Target IP: 10.0.0.20. New Scheduled Task 'UpdaterService' created"
    },
    {
        "type": "Data Exfiltration",
        "source_ip": "DB-Server-01",
        "target": "185.100.200.5",
        "timestamp": (base_time + timedelta(hours=1, minutes=30)).strftime("%Y-%m-%d %H:%M:%S"),
        "details": "Source IP: 10.0.0.20. Large upload (2GB) via HTTPS"
    }
]

def stream_callback(log_entry):
    st.session_state['agent_history'].append(log_entry)
    render_agent_logs(st.session_state['agent_history'])
    render_active_agents(st.session_state['agent_history'])
    
    # Graph update removed to prevent "Duplicate component_instance" error
    # The graph will update on the next rerun (after each alert)
    
    time.sleep(0.02)

# Layout: Sidebar
with st.sidebar:
    st.header("⚙️ 系统配置")
    
    with st.expander("API Key 设置", expanded=True):
        st.caption("配置将覆盖 .env 文件中的默认值 (仅本次会话有效)")
        
        # Use session state to hold values if they exist, else fall back to env
        default_ds_key = st.session_state.get('deepseek_api_key', os.getenv("DEEPSEEK_API_KEY", ""))
        default_vt_key = st.session_state.get('virustotal_api_key', os.getenv("VIRUSTOTAL_API_KEY", ""))
        
        deepseek_key_input = st.text_input("DeepSeek API Key", type="password", value=default_ds_key)
        vt_key_input = st.text_input("VirusTotal API Key", type="password", value=default_vt_key)
        
        if st.button("💾 保存配置"):
            st.session_state['deepseek_api_key'] = deepseek_key_input
            st.session_state['virustotal_api_key'] = vt_key_input
            st.success("配置已更新！")
            # Force reload agent with new keys
            st.session_state['agent_instance'] = Agent(
                deepseek_api_key=deepseek_key_input,
                virustotal_api_key=vt_key_input
            )

    st.markdown("---")
    st.header("🕵️‍♂️ APT 模拟")
    
    with st.expander("📖 查看剧本详情 (Lazarus APT)"):
        st.caption("点击下方按钮将依次注入以下告警：")
        for i, alert in enumerate(apt_alerts):
            st.markdown(f"**{i+1}. {alert['type']}**")
            st.text(f"源: {alert['source_ip']} -> 目的: {alert['target']}")
            st.code(json.dumps(alert, indent=2, ensure_ascii=False), language="json")

    apt_btn = st.button("▶️ 模拟 Lazarus APT 攻击链", type="primary")
    
    st.markdown("---")
    st.header("🛠️ 自定义模拟")
    custom_input = st.text_area("输入攻击思路或粘贴安全报告", height=150, placeholder="例如：模拟一个通过 Log4j 漏洞入侵 Web 服务器并挖矿的攻击链...")
    generate_btn = st.button("🎲 生成自定义剧本")

    if generate_btn and custom_input:
        with st.spinner("正在生成剧本..."):
            try:
                generator = ScenarioGenerator("Generator",
                    api_key=st.session_state.get('deepseek_api_key'),
                    vt_api_key=st.session_state.get('virustotal_api_key')
                )
                custom_scenario = generator.generate_scenario(custom_input)
                if custom_scenario:
                    st.session_state['custom_scenario'] = custom_scenario
                    st.success("剧本生成成功！")
                else:
                    st.error("生成失败，请重试")
            except Exception as e:
                st.error(f"生成失败: {e}")

    if st.session_state.get('custom_scenario'):
        with st.expander("📖 查看自定义剧本", expanded=True):
            st.json(st.session_state['custom_scenario'])
        
        custom_run_btn = st.button("▶️ 运行自定义剧本", type="primary")
    else:
        custom_run_btn = False

    st.markdown("---")
    st.header("⚙️ 图谱设置")
    graph_height = st.slider("图谱高度", 400, 1000, 600, key="graph_height_slider")
    graph_width = st.slider("图谱宽度", 400, 1200, 700, key="graph_width_slider")
    
    if st.button("🗑️ 清空知识图谱"):
        try:
            requests.post("http://localhost:8000/graph/clear")
            st.success("图谱已清空")
            time.sleep(1)
            st.rerun()
        except Exception as e:
            st.error(f"清空失败: {e}")

# Layout: Main Area
st.subheader("👥 安全运营团队 (SOC Team)")
agents_placeholder = st.empty()
st.markdown("---")

col1, col2, col3 = st.columns([1, 1, 1])

# Placeholders for dynamic updates
with col1:
    st.subheader("📋 实时告警队列")
    alert_queue_container = st.container(height=300)
    
    st.subheader("🕸️ 知识图谱 (Knowledge Graph)")
    graph_placeholder = st.empty()

with col2:
    st.subheader("🧠 Agent 思维链 (Chain of Thought)")
    log_placeholder = st.empty()
    
    st.subheader("📄 调查报告 (Investigation Report)")
    report_placeholder = st.empty()

with col3:
    st.subheader("👮‍♂️ 人工决策 (Human-in-the-Loop)")
    approval_placeholder = st.empty()
    st.subheader("📜 决策历史")
    decision_history_container = st.container(height=200)

def fetch_graph_data():
    try:
        response = requests.get("http://localhost:8000/graph")
        if response.status_code == 200:
            return response.json()
    except:
        return None
    return None

def draw_graph(graph_data, key=None):
    if not graph_data:
        st.info("等待图谱数据生成...")
        return

    # Check if nodes exist and are not empty
    if 'nodes' not in graph_data or not graph_data['nodes']:
        st.info("暂无图谱数据 (节点为空)")
        return
    
    try:
        nodes = []
        edges = []
        
        # Process Nodes
        for node in graph_data.get('nodes', []):
            # node is a dict like {'id': 'IP:1.2.3.4', 'type': 'IP', 'value': '1.2.3.4', ...}
            node_id = node.get('id')
            if not node_id: continue # Skip invalid nodes

            label = node.get('value', node_id)
            
            # Determine color/icon based on type or attributes
            color = "#00CCF1" # Default blue
            if node.get('type') == 'Attacker' or node.get('role') == 'source' or node.get('malicious'):
                color = "#FF4B4B" # Red for malicious
            elif node.get('type') == 'User':
                color = "#FFA500" # Orange for users
            
            nodes.append(Node(id=node_id, label=label, size=25, color=color))

        # Process Edges
        for link in graph_data.get('links', []):
            # link is a dict like {'source': 'id1', 'target': 'id2', 'relation': '...'}
            source = link.get('source')
            target = link.get('target')
            
            if not source or not target: continue # Skip invalid edges

            label = link.get('relation', '')
            
            edges.append(Edge(source=source, target=target, label=label, color="#000000"))

        if not nodes:
             st.info("暂无有效节点数据")
             return

        # Configuration
        # Get dimensions from session state or use defaults
        g_height = st.session_state.get("graph_height_slider", 600)
        g_width = st.session_state.get("graph_width_slider", 700)
        
        config = Config(width=g_width, 
                        height=g_height, 
                        directed=True,
                        physics=True, 
                        hierarchical=False,
                        nodeHighlightBehavior=True, 
                        highlightColor="#F7A7A6",
                        collapsible=False,
                        backgroundColor="#FFFFFF") # White background for black edges

        # Render Graph
        # Note: agraph does not support 'key' argument in some versions, removing it to fix error
        return_value = agraph(nodes=nodes, 
                              edges=edges, 
                              config=config)
                              
    except Exception as e:
        print(f"绘图失败: {e}")

def render_active_agents(logs):
    """
    Renders the team of engineers and highlights the active one based on logs.
    """
    # Determine active agent from the last log entry
    active_agent = None
    if logs:
        last_log = logs[-1]
        if "[Triage]" in last_log:
            active_agent = "Triage"
        elif "[Forensics]" in last_log:
            active_agent = "Forensics"
        elif "[Commander]" in last_log:
            active_agent = "Commander"
        elif "[Reporter]" in last_log:
            active_agent = "Reporter"
    
    agents = [
        {"id": "Triage", "name": "分诊工程师", "role": "Triage Analyst", "icon": "🔍"},
        {"id": "Forensics", "name": "取证工程师", "role": "Forensic Investigator", "icon": "🕵️‍♂️"},
        {"id": "Commander", "name": "响应工程师", "role": "Incident Commander", "icon": "🛡️"},
        {"id": "Reporter", "name": "报告工程师", "role": "Reporter", "icon": "📝"}
    ]
    
    # Start container
    html_parts = ['<div style="display: flex; justify-content: space-between; margin-bottom: 20px; gap: 10px;">']
    
    for agent in agents:
        is_active = (agent['id'] == active_agent)
        bg_color = "#e6f3ff" if is_active else "#f0f2f6"
        border_color = "#2196F3" if is_active else "#e0e0e0"
        opacity = "1.0" if is_active or active_agent is None else "0.6"
        status_text = "正在工作中..." if is_active else "待命"
        status_color = "#2196F3" if is_active else "#666"
        box_shadow = '0 4px 6px rgba(0,0,0,0.1)' if is_active else 'none'
        
        # Build card HTML in a single line to avoid markdown indentation issues
        card = (
            f'<div style="flex: 1; background-color: {bg_color}; border: 2px solid {border_color}; '
            f'border-radius: 10px; padding: 15px; text-align: center; opacity: {opacity}; '
            f'transition: all 0.3s ease; box-shadow: {box_shadow};">'
            f'<div style="font-size: 32px; margin-bottom: 10px;">{agent["icon"]}</div>'
            f'<div style="font-weight: bold; font-size: 16px; color: #31333F;">{agent["name"]}</div>'
            f'<div style="font-size: 12px; color: #666; margin-bottom: 8px;">{agent["role"]}</div>'
            f'<div style="font-size: 12px; color: {status_color}; font-weight: bold; '
            f'background-color: rgba(255,255,255,0.5); padding: 4px 8px; border-radius: 12px; display: inline-block;">'
            f'{status_text}</div></div>'
        )
        html_parts.append(card)
        
    html_parts.append('</div>')
    
    # Join with no newlines to be safe
    final_html = "".join(html_parts)
    
    agents_placeholder.markdown(final_html, unsafe_allow_html=True)

def render_agent_logs(logs):
    if not logs:
        content = "<div style='color: #666;'>[System] 等待任务启动...</div>"
    else:
        # Reverse logs so the latest (last in list) becomes the first in HTML
        # With flex-direction: column-reverse, the first HTML element is at the bottom
        reversed_logs = logs[::-1]
        content = "".join([f"<div style='margin-bottom: 4px; white-space: pre-wrap; overflow-wrap: break-word;'>{html.escape(line)}</div>" for line in reversed_logs])

    html_content = f"""
    <div style="
        height: 400px;
        overflow-y: auto;
        display: flex;
        flex-direction: column-reverse;
        border: 1px solid #e0e0e0;
        border-radius: 0.5rem;
        padding: 10px;
        background-color: #f0f2f6;
        font-family: 'Source Code Pro', monospace;
        font-size: 14px;
        color: #31333F;
        line-height: 1.5;
    ">
        {content}
    </div>
    """
    log_placeholder.markdown(html_content, unsafe_allow_html=True)

def render_alert_queue(active_index=-1):
    with alert_queue_container:
        if not st.session_state['alert_queue']:
            st.info("暂无告警")
        else:
            # Show last 5 alerts reversed
            for i, alert in enumerate(reversed(st.session_state['alert_queue'])):
                real_index = len(st.session_state['alert_queue']) - 1 - i
                is_active = (real_index == active_index)
                
                icon = "🔥" if is_active else "🕒"
                status = "**[正在处理]**" if is_active else ""
                
                # Extract details safely
                details = alert.get('details', alert.get('payload', ''))
                target = alert.get('target', 'Unknown')

                st.markdown(f"""
                <div style="padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 5px; background-color: {'#fff3cd' if is_active else 'white'}; color: black;">
                    {icon} <strong>{alert['type']}</strong> <br>
                    <small>{alert['timestamp']} | Src: {alert['source_ip']} -> Dst: {target}</small> <br>
                    <small style="color: #666;">{details}</small> <br>
                    {status}
                </div>
                """, unsafe_allow_html=True)

def render_decision_history():
    with decision_history_container:
        if not st.session_state['decision_history']:
            st.text("暂无历史记录")
        else:
            for item in reversed(st.session_state['decision_history']):
                st.markdown(f"- {item}")

def render_pending_approvals():
    with approval_placeholder.container():
        if not st.session_state.get('pending_approvals'):
            st.info("暂无待审批事项")
        else:
            st.warning(f"⚠️ 有 {len(st.session_state['pending_approvals'])} 个待审批事项")
            
            # Iterate through a copy to allow modification
            for i, item in enumerate(list(st.session_state['pending_approvals'])):
                info = item['info']
                ts = item['timestamp']
                unique_key = item.get('id', i)
                
                try:
                    # Format: "PENDING_APPROVAL: action | Reason: reason"
                    # But info is already "PENDING_APPROVAL: ..." or just the content
                    clean_info = info.replace("PENDING_APPROVAL:", "").strip()
                    parts = clean_info.split("| Reason:")
                    action = parts[0].strip()
                    reason = parts[1].strip() if len(parts) > 1 else "No reason provided"
                    
                    with st.expander(f"待审批: {action} ({ts})", expanded=True):
                        st.write(f"**原因:** {reason}")
                        c1, c2 = st.columns(2)
                        
                        if c1.button("✅ 批准", key=f"approve_{unique_key}_{i}"):
                            st.success(f"已批准: {action}")
                            st.session_state['decision_history'].append(f"✅ 批准: {action} ({time.strftime('%H:%M:%S')})")
                            
                            # Inject into agent history
                            if st.session_state.get('agent_instance'):
                                 st.session_state['agent_instance'].history.append(f"[System] 用户已批准: {action}")
                                 # Also update the displayed logs
                                 st.session_state['agent_history'].append(f"[System] 用户已批准: {action}")
                            
                            st.session_state['pending_approvals'].remove(item)
                            st.rerun()
                            
                        if c2.button("❌ 拒绝", key=f"deny_{unique_key}_{i}"):
                            st.error(f"已拒绝: {action}")
                            st.session_state['decision_history'].append(f"❌ 拒绝: {action} ({time.strftime('%H:%M:%S')})")
                            
                            # Inject into agent history
                            if st.session_state.get('agent_instance'):
                                 st.session_state['agent_instance'].history.append(f"[System] 用户已拒绝: {action}")
                                 st.session_state['agent_history'].append(f"[System] 用户已拒绝: {action}")

                            st.session_state['pending_approvals'].remove(item)
                            st.rerun()
                except Exception as e:
                    st.error(f"解析失败: {e}")

# Logic Handling
def start_simulation(alerts, status_msg):
    st.session_state['agent_history'] = []
    st.session_state['agent_status'] = status_msg
    st.session_state['agent_report'] = ""
    st.session_state['alert_queue'] = []
    st.session_state['pending_approvals'] = []
    st.session_state['decision_history'] = []
    st.session_state['simulation_running'] = True
    st.session_state['processed_alerts_count'] = 0
    st.session_state['agent_instance'] = Agent(
        deepseek_api_key=st.session_state.get('deepseek_api_key'),
        virustotal_api_key=st.session_state.get('virustotal_api_key')
    )
    st.session_state['active_scenario_alerts'] = alerts
    
    # Clear graph
    try:
        requests.post("http://localhost:8000/graph/clear")
    except:
        pass
    st.rerun()

if apt_btn:
    start_simulation(apt_alerts, "Running Lazarus APT Scenario...")

if custom_run_btn:
    start_simulation(st.session_state['custom_scenario'], "Running Custom Scenario...")

# Persist state on rerun (Render UI before processing)
render_alert_queue()
render_decision_history()

# Always render logs, even if empty, to show the box
render_agent_logs(st.session_state.get('agent_history', []))
render_active_agents(st.session_state.get('agent_history', []))

if 'agent_report' in st.session_state and st.session_state['agent_report']:
    report_placeholder.markdown(st.session_state['agent_report'])

# Show Graph
g_data = fetch_graph_data()
with graph_placeholder.container():
    draw_graph(g_data)

# Handle Approval
render_pending_approvals()

if st.session_state['simulation_running']:
    agent = st.session_state['agent_instance']
    start_idx = st.session_state['processed_alerts_count']
    current_alerts = st.session_state.get('active_scenario_alerts', apt_alerts)
    
    with st.spinner(f'正在模拟攻击链 ({st.session_state.get("agent_status", "Running")})...'):
        if start_idx < len(current_alerts):
            i = start_idx
            alert = current_alerts[i]
            
            # Add to queue
            st.session_state['alert_queue'].append(alert)
            render_alert_queue(active_index=len(st.session_state['alert_queue'])-1)
            
            # Process alert
            status, history, _ = agent.think(alert, stream_callback=stream_callback, skip_report=True)
            
            # Check for pause/approval
            if "PENDING_APPROVAL_ASYNC" in status:
                approval_info = status.split("PENDING_APPROVAL_ASYNC:")[1].strip()
                st.session_state['pending_approvals'].append({
                    "info": approval_info,
                    "timestamp": time.strftime("%H:%M:%S"),
                    "id": f"{int(time.time())}_{i}"
                })
                st.session_state['agent_status'] = "Running (Pending Approvals)"
                # Force render approvals immediately
                render_pending_approvals()
            
            # Update progress immediately
            st.session_state['processed_alerts_count'] = i + 1
            
            # Wait a bit
            time.sleep(1)
            st.rerun()
            
        # Check if done
        elif st.session_state['processed_alerts_count'] >= len(current_alerts):
            stream_callback("[System] 所有告警处理完毕，正在生成案件汇总报告...")
            final_report = agent.generate_case_report(stream_callback=stream_callback)
            
            st.session_state['agent_status'] = "Scenario Completed"
            st.session_state['agent_report'] = final_report
            st.session_state['simulation_running'] = False
            
            if final_report:
                report_placeholder.markdown(final_report)
                
            # Final Graph Update - Removed to avoid duplicate call (already called at start of run)
            # g_data = fetch_graph_data()
            # with graph_placeholder.container():
            #    draw_graph(g_data)
                
    render_alert_queue(active_index=-1)
