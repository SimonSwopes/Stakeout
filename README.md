# Decentralized AI-Driven Cyber Threat Detection System

![image description](assets/stakeout_logo.jpeg)

## Overview
A system for training a model on a dataset of network traffic data to detect cyber threats. The system is to eventually store detected threats in a decentralized secure location. The system is also designed to be AI-driven, with the model being trained using machine learning techniques.

### TODO:
- Fine tune model  
- Unit Tests with PyTest
- Store a trained model
- decouple training from running model
- create a data visualizer
- Implement decentralized storage  


### Potential Future Enhancements
- System that allows an already trained model to monitor a stream of activity and automatically detect threats in real-time
- Data visualization tools to help users understand the data and the model's predictions
   - May be a septate project that utilizes this one

### Sources
 - **Training Dataset:** https://www.unb.ca/cic/datasets/ids-2017.html
    - ***Provider:*** Canadian Institute for Cybersecurity


## Layout

### Setup
This project, in it's current state, is mainly setup in way to make it easy for me to run and test.
- **Note**: Directory paths are expected to be backslash separated
- **Prerequisites:**
    - Python 3.13 or higher
    - pip
- **Requirements**: `pip install -r requirements.txt`
- Help: `python main.py -h`
   - The testing and validation flags expect a directory to the csv files from the linked dataset.
   - The output directory flag is just where some log files will go. Logging is also done in the console.
   - Only the training flag is required as validation is optional and output defaults to logs/
- **Data**: The linked data set may download with column names preceded by a space
   - I have not fixed this yet and is not supported by the program. You will need to remove the space from the columns listed as feature_nodes and target_node src\lib\constants.py

### Scripts
- `./scripts/reset`
   - This will rm `__pycache__` and any files ending in `.log`
- `./scripts/run [size] (validate)`
   - This will run the program main python program with some default args
   - Size ('small' | 'large')
      - Will use `data\small\training` and `data\small\validate` to search for csv
      - Ensure a good split of the data across these directories
   - Validate (optional)
      - simply type validate to run the program with validation from the validate 

### Program Behavior
The program is essentially an implementation of the builder pattern to the extent that this could be done in a pythonic way.

Other than some standard setup for argparse, a wrapper for the logger, a wrapper for data loading, the application is centered around 3 classes essentially form a linear hierarchy of dependencies.

Working from the bottom up how the builder is going through these:
- **NetworkActivityDataStreamer**
   - Not really a data streamer at the moment
   - Takes an instance of the logger and loader
   - Loads & Formats from either the training or validating directory on initialization
   - Creates mock ip addresses for the data
   - Validates data contains the columns expected
   - Other than that behaves as a wrapper for a pandas DataFame most methods are just pass troughs
- **NetworkMonitorModel**
   - Takes a logger and a NetworkActivityDataStreamer for training data and a NetworkActivityDataStreamer for validation data
   - If the validation streamer is none the object will still instantiate but calls to Validate will return an empty list and log a warning
   - On instantiation it will train and evaluate the model on the training data stream.
   - The trained model is a regression model that predicts the target node based on the feature nodes.`(See src/lib/constants.py for the column names)`
   - ***Validate Method***: Will run on validation data accepts threshold float (0.5 default) and will perform predictions on validation data by and filtering probabilities based on the threshold. As well as perform some logging on the classification report. Will return a list of the value column of the validation data predictions.
- **SecureNetworkMonitor**
   - Simply an abstraction of the NetworkMonitorModel to make interaction more intuitive.
   - Takes a logger and a NetworkMonitorModel
   - Has a single method `detect_malicious_ips()` but will likely be expanded on.
   - This is a pass through to the NetworkMonitorModel's validate method with a default threshold of 0.5  

Other than the above, the program is simply passing CLI args to the builder and running the returned SecureNetworkMonitor's detect_malicious_ips method.


### Logs
- Logs are stored in the logs directory `logs/` by default
- `application.log` is the main log file for the program (logged to console as well)
- `classification_report.log` is the log file for the classification report from the evaluation step.
- `validation_report.log` is the log file for the validation data predictions
- `malicious_ips.log` a list of the predicted malicious ips from validation stage