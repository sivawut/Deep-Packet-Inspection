Library Requirement
--python3 global installation--

#sudo pipx install mitmproxy
#sudo apt install python3-pip -y
#sudo apt install python3-sklearn python3-joblib



To run this project

We have to start the mitm by this command

#sudo mitmdump -s ml3.py --mode transparent -p 8080 --quiet

The mitmdump will use ml3.py as a scrip to process http/https header check
