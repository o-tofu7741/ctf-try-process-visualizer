import pandas as pd
import networkx as nx
import plotly.graph_objects as go
from analyze import parse_audit_logs

# 1. データの読み込みと前処理
# analyze.pyのparse_audit_logs関数を呼び出してデータを取得
log_data = parse_audit_logs()

# データをDataFrameに変換
log_df = pd.DataFrame(log_data)

# タイムスタンプをdatetime型に変換
log_df['time_stamp'] = pd.to_datetime(log_df['time_stamp'])

# CTF開始時刻とFLAG取得時刻を特定
ctf_start_time = log_df['time_stamp'].min()
flag_time = log_df[log_df['cwe_id'] == 'FLAG']['time_stamp'].min()

# 通信元IPごとにグループ化し、CWE-idの遷移を記録
grouped_data = log_df.groupby('client_ip')['cwe_id'].apply(list)

# 2. グラフの構築
G = nx.DiGraph()

# CWE-idをノードとして追加
for cwe_id in log_df['cwe_id'].unique():
    G.add_node(cwe_id)

# CTF開始ノードとFLAGノードを追加
G.add_node('CTF_START')
G.add_node('FLAG')

# 通信元IPごとのCWE-idの遷移をエッジとして追加
for ip, cwe_ids in grouped_data.items():
    G.add_edge('CTF_START', cwe_ids[0], source_ip=ip)
    for i in range(len(cwe_ids) - 1):
        G.add_edge(cwe_ids[i], cwe_ids[i + 1], source_ip=ip)
    if 'FLAG' in cwe_ids:
        G.add_edge(cwe_ids[-1], 'FLAG', source_ip=ip)

# 3. グラフの可視化
pos = nx.spring_layout(G)
edge_trace = []
for edge in G.edges(data=True):
    x0, y0 = pos[edge[0]]
    x1, y1 = pos[edge[1]]
    edge_trace.append(go.Scatter(
        x=[x0, x1, None],
        y=[y0, y1, None],
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines'))

node_trace = go.Scatter(
    x=[],
    y=[],
    text=[],
    mode='markers+text',
    hoverinfo='text',
    marker=dict(
        showscale=True,
        colorscale='YlGnBu',
        size=10,
        colorbar=dict(
            thickness=15,
            title='CWE-id',
            xanchor='left',
            titleside='right'
        ),
    )
)

for node in G.nodes():
    x, y = pos[node]
    node_trace['x'] += (x,)
    node_trace['y'] += (y,)
    node_trace['text'] += (f'CWE-id: {node}',)

fig = go.Figure(data=edge_trace + [node_trace],
                layout=go.Layout(
                    title='CWE-id遷移グラフ',
                    titlefont_size=16,
                    showlegend=False,
                    hovermode='closest',
                    margin=dict(b=20, l=5, r=5, t=40),
                    annotations=[dict(
                        text="CWE-id遷移グラフ",
                        showarrow=False,
                        xref="paper", yref="paper"
                    )],
                    xaxis=dict(showgrid=False, zeroline=False),
                    yaxis=dict(showgrid=False, zeroline=False))
                )

fig.show()
