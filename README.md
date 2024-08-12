# Simple-Intrusion-Detection-System(IDS)

simple-intrusion-detection-system designed to monitor network traffic and apply custom rules to detect and respond to various types of network activity.

## Getting Started

### Prerequisites

Before you begin, ensure you have Python installed on your system. It is recommended to use a virtual environment to manage dependencies.

### Setting Up a Virtual Environment

1. **Create a virtual environment**:

    ```bash
    virtualenv venv
    ```

2. **Activate the virtual environment**:

    ```bash
    source venv/bin/activate
    ```

### Installing Dependencies

Once the virtual environment is activated, install the required dependencies:

```bash
pip install -r requirements.txt
```
### Configuring Alerts

**If you intend to use the alert feature, you'll need to configure the alert endpoint in rule.py**"

```# In rule.py
webhook_url = 'https://your-alert-endpoint.com'
```

### Customizing Rules

**Rules determine how the IDS will react to different types of network traffic. Customize the rules.txt file to define your detection logic.**

```# Rule Format
protocol src_ip:src_port -> dst_ip:dst_port action message
```

### Running the IDS

```
python IDS_app.py
```



