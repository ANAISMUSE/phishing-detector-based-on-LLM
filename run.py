# run.py
import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    # 默认关闭 debug；本地开发设 FLASK_DEBUG=1 开启
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=debug)
