import requests
import os
import json
import networkx as nx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# Explicitly load .env from project root
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)

app = FastAPI(title="MCP Server & SOAR Mock Tools")

# --- Knowledge Graph ---
GRAPH_FILE = os.path.join(root_dir, 'knowledge_graph.json')

def load_graph():
    if os.path.exists(GRAPH_FILE):
        try:
            with open(GRAPH_FILE, 'r') as f:
                data = json.load(f)
            return nx.node_link_graph(data, directed=True)
        except Exception as e:
            print(f"Error loading graph: {e}")
    return nx.DiGraph()

def save_graph():
    try:
        data = nx.node_link_data(knowledge_graph)
        with open(GRAPH_FILE, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Error saving graph: {e}")

# Initialize graph
knowledge_graph = load_graph()

# --- Data Models ---
class ToolRequest(BaseModel):
    tool_name: str
    arguments: dict

class ToolResponse(BaseModel):
    status: str
    result: str

# --- Mock Tools Implementation ---

def check_ip_reputation(ip: str, api_key: str = None) -> str:
    """Checks an IP against VirusTotal if API key is present, otherwise uses mock data."""
    vt_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
    
    # Debug info for troubleshooting
    if not vt_key:
        print(f"DEBUG: VT Key is missing. Env path used: {env_path}")
    elif vt_key == "your-virustotal-key-here":
        print("DEBUG: VT Key is still the placeholder.")
    else:
        print(f"DEBUG: VT Key loaded (Length: {len(vt_key)}). Checking IP: {ip}")

    # Internal IP check
    if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172.16"):
        # Special case for our demo malicious IP
        if ip == "10.0.0.5":
             return "恶意：内部 IP，但被标记为已知的 C2 服务器 (模拟数据)。"
        return "安全：内部 IP 地址。"

    if vt_key and vt_key != "your-virustotal-key-here":
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": vt_key}
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats['malicious']
                suspicious = stats['suspicious']
                
                if malicious > 0:
                    return f"恶意：VirusTotal 发现 {malicious} 个引擎将其标记为恶意，{suspicious} 个标记为可疑。"
                else:
                    return f"安全：VirusTotal 未发现威胁 ({stats['harmless']} 个引擎标记为安全)。"
            else:
                return f"错误：VirusTotal API 调用失败 ({response.status_code})。"
        except Exception as e:
            return f"错误：连接 VirusTotal 失败 - {str(e)}"
    
    # Fallback Mock Data
    if ip == "8.8.8.8":
        return "安全：Google DNS。"
    elif ip == "1.1.1.1":
        return "安全：Cloudflare DNS。"
    elif ip == "67.203.7.205":
        return "恶意：VirusTotal 发现 10 个引擎将其标记为恶意，0 个标记为可疑。"
    else:
        return "未知：未找到相关记录 (无 VirusTotal Key)。"

def firewall_block_ip(ip: str) -> str:
    """Simulates blocking an IP on the firewall."""
    # Enforce human approval for all block operations
    return f"PENDING_APPROVAL: Block IP {ip} | Reason: High-risk operation (Firewall Block) requires human confirmation."

def analyze_payload(payload: str) -> str:
    """Analyzes a payload using an LLM to identify the specific attack type."""
    # Try to use LLM for analysis if API key is available
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if api_key:
        try:
            client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
            response = client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": "You are a malware analyst. Analyze the provided payload. Return a short, specific attack category (e.g., 'SQL Injection', 'XSS', 'Command Execution', 'Brute Force'). Return ONLY the category name. If benign, return 'Benign'."},
                    {"role": "user", "content": f"Payload: {payload}"}
                ],
                stream=False
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"LLM analysis failed: {e}")

    # Fallback mock logic
    if "UNION SELECT" in payload.upper() or "OR 1=1" in payload:
        return "SQL Injection"
    return "Suspicious Activity"

# --- Graph Tools ---

def graph_add_entity(entity_type: str, entity_value: str, attributes: Dict[str, Any] = {}) -> str:
    """Adds an entity (node) to the knowledge graph."""
    node_id = f"{entity_type}:{entity_value}"
    knowledge_graph.add_node(node_id, type=entity_type, value=entity_value, **attributes)
    save_graph()
    return f"已添加实体: {node_id}"

def graph_add_relation(source_type: str, source_value: str, relation: str, target_type: str, target_value: str) -> str:
    """Adds a relationship (edge) between two entities."""
    source_id = f"{source_type}:{source_value}"
    target_id = f"{target_type}:{target_value}"
    
    if not knowledge_graph.has_node(source_id):
        knowledge_graph.add_node(source_id, type=source_type, value=source_value)
    if not knowledge_graph.has_node(target_id):
        knowledge_graph.add_node(target_id, type=target_type, value=target_value)
        
    knowledge_graph.add_edge(source_id, target_id, relation=relation)
    save_graph()
    return f"已添加关系: {source_id} --[{relation}]--> {target_id}"

def graph_query(entity_type: str, entity_value: str) -> str:
    """Queries the graph for related entities."""
    node_id = f"{entity_type}:{entity_value}"
    if not knowledge_graph.has_node(node_id):
        return "未在图谱中找到该实体。"
    
    neighbors = knowledge_graph.neighbors(node_id)
    results = []
    for neighbor in neighbors:
        edge_data = knowledge_graph.get_edge_data(node_id, neighbor)
        relation = edge_data.get('relation', 'related_to')
        results.append(f"- [{relation}] -> {neighbor}")
    
    if not results:
        return "该实体在图谱中是孤立的。"
    
    return "关联实体:\n" + "\n".join(results)

def ask_human_approval(action: str, reason: str) -> str:
    """
    Requests human approval for a critical action.
    Returns a special token that the Agent should interpret as 'Wait'.
    """
    return f"PENDING_APPROVAL: {action} | Reason: {reason}"

# --- API Endpoints ---

@app.get("/")
def health_check():
    return {"status": "running", "service": "MCP Server"}

@app.get("/tools")
def list_tools():
    """Returns the list of available tools (MCP capability)."""
    return [
        {
            "name": "check_ip_reputation",
            "description": "Check if an IP address is malicious.",
            "parameters": {"type": "object", "properties": {"ip": {"type": "string"}}}
        },
        {
            "name": "firewall_block_ip",
            "description": "Block an IP address on the firewall.",
            "parameters": {"type": "object", "properties": {"ip": {"type": "string"}}}
        },
        {
            "name": "analyze_payload",
            "description": "Analyze a string payload for malicious patterns.",
            "parameters": {"type": "object", "properties": {"payload": {"type": "string"}}}
        },
        {
            "name": "graph_add_entity",
            "description": "Add an entity to the investigation knowledge graph.",
            "parameters": {
                "type": "object", 
                "properties": {
                    "entity_type": {"type": "string", "description": "e.g., IP, User, Host"},
                    "entity_value": {"type": "string"},
                    "attributes": {"type": "object"}
                },
                "required": ["entity_type", "entity_value"]
            }
        },
        {
            "name": "graph_add_relation",
            "description": "Add a relationship between two entities in the graph.",
            "parameters": {
                "type": "object", 
                "properties": {
                    "source_type": {"type": "string"},
                    "source_value": {"type": "string"},
                    "relation": {"type": "string", "description": "e.g., ATTACKED, LOGGED_IN_TO"},
                    "target_type": {"type": "string"},
                    "target_value": {"type": "string"}
                },
                "required": ["source_type", "source_value", "relation", "target_type", "target_value"]
            }
        },
        {
            "name": "graph_query",
            "description": "Find related entities in the knowledge graph.",
            "parameters": {
                "type": "object", 
                "properties": {
                    "entity_type": {"type": "string"},
                    "entity_value": {"type": "string"}
                },
                "required": ["entity_type", "entity_value"]
            }
        },
        {
            "name": "ask_human_approval",
            "description": "Request human approval before executing high-risk actions (like blocking critical servers).",
            "parameters": {
                "type": "object", 
                "properties": {
                    "action": {"type": "string", "description": "The action to perform"},
                    "reason": {"type": "string", "description": "Why this action is needed"}
                },
                "required": ["action", "reason"]
            }
        }
    ]

@app.get("/graph")
def get_graph():
    """Returns the current state of the knowledge graph."""
    return nx.node_link_data(knowledge_graph)

@app.post("/graph/clear")
def clear_graph():
    """Clears the knowledge graph."""
    global knowledge_graph
    knowledge_graph.clear()
    save_graph()
    return {"status": "success", "message": "Graph cleared"}

@app.post("/execute", response_model=ToolResponse)
def execute_tool(request: ToolRequest):
    """Executes a requested tool."""
    tool_name = request.tool_name
    args = request.arguments
    
    print(f"Agent requested tool: {tool_name} with args: {args}")

    try:
        if tool_name == "check_ip_reputation":
            result = check_ip_reputation(args.get("ip"), args.get("api_key"))
        elif tool_name == "firewall_block_ip":
            result = firewall_block_ip(args.get("ip"))
        elif tool_name == "analyze_payload":
            result = analyze_payload(args.get("payload"))
        elif tool_name == "graph_add_entity":
            result = graph_add_entity(
                args.get("entity_type"), 
                args.get("entity_value"), 
                args.get("attributes", {})
            )
        elif tool_name == "graph_add_relation":
            result = graph_add_relation(
                args.get("source_type"), 
                args.get("source_value"), 
                args.get("relation"), 
                args.get("target_type"), 
                args.get("target_value")
            )
        elif tool_name == "graph_query":
            result = graph_query(args.get("entity_type"), args.get("entity_value"))
        elif tool_name == "ask_human_approval":
            result = ask_human_approval(args.get("action"), args.get("reason"))
        else:
            raise HTTPException(status_code=404, detail="Tool not found")
        
        return ToolResponse(status="success", result=result)
    except Exception as e:
        return ToolResponse(status="error", result=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
