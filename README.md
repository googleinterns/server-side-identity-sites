# Google Identity Service Mock Website and Code Generator

## Project Overview
The purpose of this project is to create a suite of tools to assist developers with the server-side integration of Google Sign In products into their web applications. This repository contains the mock website Networkr which serves as an example of proper UX flow for Google Sign In. The repository also contains an example of a server-side code generator for use in the integration process. Both of these applications have been implemented in Python using the Flask web server framework.

## Installation
The mock website and code generator can be run locally from the command line. To begin, download this repository using the following command:
~~~
git clone https://github.com/sotremba/server-side-identity-sites.git
~~~
Once downloaded, the proper dependencies must be installed to run the server. To install the packages managed by PyPI, run the following:
~~~
pip install -r requirements.txt
~~~
Next, we must download the Google Identity Service server-side integration library, which is currenlty unreleased on PyPI and can be found on Github [here](https://github.com/googleinterns/server-side-identity). Follow the steps in that repository's README to download and set up this library in a neighboring directory.

## Running the Server
Once installed, the server can be run by executing the following commands inside the repository directory:
~~~
export FLASK_APP=main.py
flask run
~~~
This will run the server which will begin serving content at the default port 5000

## Accessing the Mock Website
Once the server is running, open any browser and navigate to http://localhost:5000/. This will bring you to the home page of the Networkr mock website. From there, you can practice making making and logging into accounts either traditionally or through Google Sign In.

## Accessing the code Generator
Once the server is running, open any browser and navigate to http://localhost:5000/generator. This will bring you to the input form for the server side code generator. Enter your desired parameters and generate your code which will be displayed on the right.

## Closing the Server
Once you've finished navigating Networkr and the code generator, you can terminate the server by executing Ctrl + C in the terminal


### Disclaimer
This is not an officially supported Google product.
