from dash import Dash, html, dcc, Input, Output

app = Dash(__name__)

app.layout = html.Div([
    dcc.Graph(id='network-graph', figure=fig),
    html.Div(id='node-info')
])

@app.callback(
    Output('node-info', 'children'),
    Input('network-graph', 'clickData')
)
def display_node_info(clickData):
    if clickData is not None:
        node = clickData['points'][0]['text']
        # ノードに対応する詳細情報を取得
        return f'選択したノード: {node}'
    return 'ノードをクリックすると詳細が表示されます。'

if __name__ == '__main__':
    app.run_server(debug=False)
