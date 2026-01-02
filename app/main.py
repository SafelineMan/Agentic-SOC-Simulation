import streamlit as st
import requests
import json
import time
import pandas as pd
from datetime import datetime, timedelta
import sys
import os
import html
import markdown
import networkx as nx
import matplotlib.pyplot as plt
import textwrap
from streamlit_agraph import agraph, Node, Edge, Config
import importlib

# Add the root directory to sys.path to allow importing agent modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import agent.core
import agent.ocsf
import agent.engine

importlib.reload(agent.ocsf)
importlib.reload(agent.engine)
importlib.reload(agent.core)

from agent.core import Agent

st.set_page_config(page_title="ASPS - 自主安全运营平行仿真中心", layout="wide")

st.title("🛡️ Agentic SOC Parallel Simulation (ASPS): 自主安全运营平行仿真中心")

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
    st.header("♾️ 平行仿真演练 (Parallel Simulation)")
    st.caption("从剧本生成遥测数据，自动开发规则，并验证检测效果。")
    
    default_scenario = """模拟 Lazarus 组织的一次攻击。

1. 攻击者 (IP: 45.33.22.11) 向受害者 (User-Workstation-01) 发送钓鱼邮件，附件是 invoice.exe。
2. 用户运行附件，invoice.exe 启动并连接 C2 服务器 (185.100.200.5)。
3. 攻击者进行横向移动，尝试通过 SMB 爆破 DB-Server-01。
4. 攻击者在 DB-Server-01 上建立持久化（创建计划任务 UpdaterService）。
5. 攻击者将敏感数据打包，并从 DB-Server-01 外泄到 C2 服务器 (185.100.200.5)。"""

    purple_scenario = st.text_area("输入演练剧本", value=default_scenario, height=180, key="purple_input")
    purple_btn = st.button("🚀 启动全流程演练", type="primary")



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

# Row 1
row1_col1, row1_col2, row1_col3 = st.columns([1, 1, 1])

with row1_col1:
    st.subheader("🛠️ 检测工程工作台 (Detection Engineering Workspace)")
    detection_workspace_placeholder = st.empty()

with row1_col2:
    st.subheader("📋 实时告警队列 (Real-time Alert Queue)")
    alert_queue_container = st.container(height=400)

with row1_col3:
    st.subheader("🧠 Agent 思维链 (Chain of Thought)")
    log_placeholder = st.empty()

st.markdown("---")

# Row 2
row2_col1, row2_col2, row2_col3 = st.columns([1, 1, 1])

with row2_col1:
    st.subheader("🕸️ 知识图谱 (Knowledge Graph)")
    graph_placeholder = st.empty()

with row2_col2:
    st.subheader("📄 调查报告 (Investigation Report)")
    report_container = st.container(height=400)
    with report_container:
        report_placeholder = st.empty()

with row2_col3:
    st.subheader("👮‍♂️ 人工决策 (Human-in-the-Loop)")
    approval_placeholder = st.empty()
    st.subheader("📜 决策历史 (Decision History)")
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
        elif "[PurpleTeam]" in last_log:
            active_agent = "PurpleTeam"
        elif "[DetectionEng]" in last_log:
            active_agent = "DetectionEng"
        elif "[Engine]" in last_log:
            active_agent = "Engine"
    
    # Define Agents Map with Steps
    agents_map = {
        "PurpleTeam": {"name": "紫队工程师", "role": "Purple Team", "icon": "😈", "step": 0},
        "Warehouse": {"name": "安全数仓", "role": "Data Warehouse", "icon": "🗄️", "step": 1},
        "DetectionEng": {"name": "检测工程师", "role": "Detection Eng", "icon": "🛠️", "step": 2},
        "Engine": {"name": "分析引擎", "role": "Analysis Engine", "icon": "⚙️", "step": 3},
        "Triage": {"name": "分诊工程师", "role": "Triage Analyst", "icon": "🔍", "step": 4},
        "Forensics": {"name": "取证工程师", "role": "Forensic Investigator", "icon": "🕵️‍♂️", "step": 5},
        "Commander": {"name": "响应工程师", "role": "Incident Commander", "icon": "🛡️", "step": 5},
        "Reporter": {"name": "报告工程师", "role": "Reporter", "icon": "📝", "step": 6}
    }
    
    # Find active index
    active_idx = -1
    if active_agent and active_agent in agents_map:
        active_idx = agents_map[active_agent]['step']
    
    def render_card(agent_key):
        if agent_key not in agents_map: return ""
        agent = agents_map[agent_key]
        step = agent['step']
        
        # Status Logic
        if active_idx == -1:
            status = "pending"
        elif step < active_idx:
            status = "completed"
        elif step == active_idx:
            status = "active"
        else:
            status = "pending"
            
        # Styles
        if status == "active":
            bg = "#e6f3ff"; border = "#2196F3"; opacity = "1.0"; text = "工作中"; color = "#2196F3"; shadow = "0 6px 12px rgba(33,150,243,0.4)"; transform = "scale(1.05)"
        elif status == "completed":
            bg = "#f0f9f0"; border = "#4CAF50"; opacity = "0.9"; text = "已完成"; color = "#4CAF50"; shadow = "none"; transform = "scale(1.0)"
        else:
            bg = "#f8f9fa"; border = "#e0e0e0"; opacity = "0.6"; text = "待命"; color = "#999"; shadow = "none"; transform = "scale(1.0)"
            
        return (
            f'<div style="min-width: 160px; background-color: {bg}; border: 2px solid {border}; border-radius: 12px; padding: 15px; '
            f'text-align: center; opacity: {opacity}; box-shadow: {shadow}; transform: {transform}; transition: all 0.3s; z-index: 10;">'
            f'<div style="font-size: 32px; margin-bottom: 8px;">{agent["icon"]}</div>'
            f'<div style="font-weight: bold; font-size: 16px; color: #333; margin-bottom: 4px;">{agent["name"]}</div>'
            f'<div style="font-size: 12px; color: {color}; font-weight: bold; background-color: rgba(255,255,255,0.6); padding: 4px 8px; border-radius: 10px; display: inline-block;">{text}</div>'
            f'</div>'
        )

    def render_svg_arrow(type, from_step):
        is_active = (active_idx > from_step)
        color = "#2196F3" if is_active else "#ddd"
        
        width = 120
        height = 80
        stroke_width = 3
        
        if type == "straight":
            return (
                f'<div style="display: flex; align-items: center; height: 100%;">'
                f'<svg width="{width}" height="20" viewBox="0 0 {width} 20" fill="none" xmlns="http://www.w3.org/2000/svg">'
                f'<path d="M0 10 H{width-10}" stroke="{color}" stroke-width="{stroke_width}" stroke-linecap="round"/>'
                f'<path d="M{width-10} 10 L{width-20} 5 M{width-10} 10 L{width-20} 15" stroke="{color}" stroke-width="{stroke_width}" stroke-linecap="round" stroke-linejoin="round"/>'
                f'</svg></div>'
            )
        elif type == "arrow_down":
            return (
                f'<div style="display: flex; justify-content: center; height: 40px; width: 100%;">'
                f'<svg width="40" height="40" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">'
                f'<path d="M20 0 V30" stroke="{color}" stroke-width="{stroke_width}" stroke-linecap="round"/>'
                f'<path d="M20 30 L15 20 M20 30 L25 20" stroke="{color}" stroke-width="{stroke_width}" stroke-linecap="round" stroke-linejoin="round"/>'
                f'</svg></div>'
            )
        elif type == "curve_down": # Start Top-Left, End Bottom-Right
            return (
                f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" fill="none" xmlns="http://www.w3.org/2000/svg">'
                f'<path d="M0 10 C{width/2} 10 {width/2} {height-10} {width-10} {height-10}" stroke="{color}" stroke-width="{stroke_width}" fill="none"/>'
                f'<path d="M{width-10} {height-10} L{width-20} {height-15} M{width-10} {height-10} L{width-20} {height-5}" stroke="{color}" stroke-width="{stroke_width}" stroke-linecap="round" stroke-linejoin="round"/>'
                f'</svg>'
            )
        elif type == "curve_up": # Start Bottom-Left, End Top-Right
            return (
                f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" fill="none" xmlns="http://www.w3.org/2000/svg">'
                f'<path d="M0 {height-10} C{width/2} {height-10} {width/2} 10 {width-10} 10" stroke="{color}" stroke-width="{stroke_width}" fill="none"/>'
                f'<path d="M{width-10} 10 L{width-20} 5 M{width-10} 10 L{width-20} 15" stroke="{color}" stroke-width="{stroke_width}" stroke-linecap="round" stroke-linejoin="round"/>'
                f'</svg>'
            )
        return ""

    # Build HTML Layout (Left to Right Flow)
    html_parts = [
        '<div style="display: flex; flex-direction: row; align-items: center; justify-content: center; gap: 0px; overflow-x: auto; padding: 30px 10px; width: 100%;">',
        
        # Col 1: PurpleTeam
        '<div>', render_card("PurpleTeam"), '</div>',
        
        # Col 2: Arrow: Purple -> Warehouse
        '<div>', render_svg_arrow("straight", 0), '</div>',
        
        # Col 3: Warehouse -> DetectionEng (Vertical Stack)
        '<div style="display: flex; flex-direction: column; align-items: center; gap: 0px;">',
        render_card("Warehouse"),
        render_svg_arrow("arrow_down", 1),
        render_card("DetectionEng"),
        '</div>',
        
        # Col 4: Merge Arrows (Warehouse -> Engine, Detection -> Engine)
        '<div style="display: flex; flex-direction: column; gap: 0px; justify-content: center;">',
        render_svg_arrow("curve_down", 1), # Warehouse -> Engine
        render_svg_arrow("curve_up", 2),   # Detection -> Engine
        '</div>',
        
        # Col 5: Engine
        '<div>', render_card("Engine"), '</div>',
        
        # Col 6: Arrow: Engine -> Triage
        '<div>', render_svg_arrow("straight", 3), '</div>',
        
        # Col 7: Triage
        '<div>', render_card("Triage"), '</div>',
        
        # Col 8: Split Arrows: Triage -> Forensics/Commander
        '<div style="display: flex; flex-direction: column; gap: 0px; justify-content: center;">',
        render_svg_arrow("curve_up", 4),
        render_svg_arrow("curve_down", 4),
        '</div>',
        
        # Col 9: Parallel Ops: Forensics, Commander
        '<div style="display: flex; flex-direction: column; gap: 30px;">',
        render_card("Forensics"),
        render_card("Commander"),
        '</div>',
        
        # Col 10: Merge Arrows: Forensics/Commander -> Reporter
        '<div style="display: flex; flex-direction: column; gap: 0px; justify-content: center;">',
        render_svg_arrow("curve_down", 5),
        render_svg_arrow("curve_up", 5),
        '</div>',
        
        # Col 11: Reporter
        '<div>', render_card("Reporter"), '</div>',
        
        '</div>'
    ]
    
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



if purple_btn and purple_scenario:
    # Initialize agent temporarily to run prep
    temp_agent = Agent(
        deepseek_api_key=st.session_state.get('deepseek_api_key'),
        virustotal_api_key=st.session_state.get('virustotal_api_key')
    )
    
    st.session_state['agent_history'] = []
    
    # Step 1: Generate Telemetry
    with st.spinner("Step 1/3: 紫队正在生成攻击遥测数据..."):
        telemetry = temp_agent.run_purple_step1_gen_data(purple_scenario, stream_callback=stream_callback)
        if telemetry:
            st.session_state['telemetry_data'] = telemetry
            st.success(f"✅ 数据入库完成！生成 {len(telemetry)} 条遥测日志。")
            time.sleep(1)
        else:
            st.error("遥测生成失败")
            st.stop()

    # Step 2: Develop Rules
    with st.spinner("Step 2/3: 检测工程师正在开发规则..."):
        rules = temp_agent.run_purple_step2_dev_rules(telemetry, purple_scenario, stream_callback=stream_callback)
        if rules:
            st.session_state['generated_rules'] = rules
            st.success(f"✅ 规则开发完成！产出 {len(rules)} 条检测规则。")
            time.sleep(1)
        else:
            st.error("规则开发失败")
            st.stop()

    # Step 3: Engine Scan
    with st.spinner("Step 3/3: 分析引擎正在扫描数仓..."):
        alerts = temp_agent.run_purple_step3_engine_scan(rules, telemetry, stream_callback=stream_callback)
        if alerts:
            st.success(f"✅ 威胁检测完成！触发 {len(alerts)} 条告警。")
            time.sleep(1)
            start_simulation(alerts, "Running Purple Team Scenario...")
        else:
            st.warning("未触发任何告警 (漏报)")
            st.stop()



# Persist state on rerun (Render UI before processing)
render_alert_queue()
render_decision_history()

# Always render logs, even if empty, to show the box
render_agent_logs(st.session_state.get('agent_history', []))
render_active_agents(st.session_state.get('agent_history', []))

# Telemetry Data View (Security Data Warehouse)
st.markdown("---")
st.subheader("🗄️ 安全数仓 (Security Data Warehouse)")

if 'telemetry_data' in st.session_state and st.session_state['telemetry_data']:
    telemetry_list = st.session_state['telemetry_data']
    
    # Convert OCSF objects to dicts for display
    table_data = []
    for t in telemetry_list:
        try:
            # Handle both dict and Pydantic model
            t_dict = t.model_dump() if hasattr(t, 'model_dump') else t
            
            # Helper for safe nested get
            def safe_get(d, keys, default='N/A'):
                current = d
                for k in keys:
                    if isinstance(current, dict):
                        current = current.get(k)
                    elif hasattr(current, k):
                        current = getattr(current, k)
                    else:
                        return default
                    
                    if current is None:
                        return default
                return current

            # Extract key fields for the summary table
            row = {
                "Time": safe_get(t_dict, ['metadata', 'time']),
                "Class": safe_get(t_dict, ['class_name'], 'Unknown'),
                "Activity": safe_get(t_dict, ['activity_id']),
                "Source IP": safe_get(t_dict, ['src_endpoint', 'ip']),
                "Dest IP": safe_get(t_dict, ['dst_endpoint', 'ip']),
                "Process": safe_get(t_dict, ['actor', 'process', 'name']),
                "User": safe_get(t_dict, ['actor', 'user', 'name'])
            }
            table_data.append(row)
        except Exception as e:
            print(f"Error processing telemetry row: {e}")
            continue
        
    if table_data:
        df = pd.DataFrame(table_data)
        with st.expander("📊 遥测数据概览 (Telemetry Overview)", expanded=True):
            st.dataframe(df, use_container_width=True)
    else:
        st.info("暂无遥测数据可展示")
else:
    with st.expander("📊 遥测数据概览 (Telemetry Overview)", expanded=True):
        st.info("等待紫队生成数据入库...")

# Detection Engineering Workspace (Rendered in Row 1 Col 1)
if 'generated_rules' in st.session_state and st.session_state['generated_rules']:
    with detection_workspace_placeholder.container():
        rules = st.session_state['generated_rules']
        
        tab1, tab2 = st.tabs(["📜 规则列表", "💻 JSON 代码"])
        
        with tab1:
            for r in rules:
                # Handle Pydantic v1/v2
                r_dict = r.model_dump() if hasattr(r, 'model_dump') else r.dict()
                st.info(f"**{r_dict.get('title', 'Untitled')}**\n\nSeverity: {r_dict.get('severity', 'Low')}")
                
        with tab2:
            # Show all rules JSON
            rules_json = [r.model_dump() if hasattr(r, 'model_dump') else r.dict() for r in rules]
            st.json(rules_json, expanded=False)
else:
    with detection_workspace_placeholder.container():
        st.info("等待检测工程师产出规则...")

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
