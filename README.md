# Secure_4_inArow

## Description of the system
<p>The application implements a secure online version of the game “Four-in-a-row”. 
To make the application not vulnerable to replay attacks, Man in the Middle attacks and perturbation attacks, we have designed and validated theoretically proper Client-Server communication protocols.</p>

### How the application works?
<ul>
  <li>The user have to access the lobby of the application</li>
  <li>Then can select the type of match: CHALLENGER or CHALLENGED</li>
  <li>If the user selects CHALLENGER mode will be able to see the list of all the available players that can be challenged. Typing the username of one of those players he will send to it a match request</li>
  <li>If the user selects CHALLENGED mode, he decided to wait until the reception of a challenge request from another player. If no challenge requests are received until 5 minutes the user is redirected to main menu.</li>
  <li> Then players can start the game. The CHALLENGER player will start the match taking the first move.</li>
</ul>

### Cryptographic Algorithms used
<ul>
  <li>Authentication:
To authenticate the users (to the server and to each other) there are sent some random_data to 	authenticate. The random_data is sent in clear, on the random_data is applied a Digital Signature using the hashing function sha256 and the private key of the sending user.</li>
  <li>Session key creation:
To create the session key has been used the standard version of Diffie-Hellman and on every message sent is applied the Digital Signature (since Diffie Hellman does not authenticate the parties). At the end when all the parties have the session key, the session key is hashed using sha256.</li>
<li>Message Exchange:
Now both ends have the session key now the AES GCM is used to send the secrets. Since our messages are all encrypted despite the IV, the AAD used is the same as the IV of the messages.</li>



#### Full documentation
<p> More details on the communication protocols and their theoretical validation can be found in the project documentation.<p>
<p> The full documentation is available in this repository! (https://github.com/rafnocerino/Secure_4_inArow/blob/master/docs/FoC%20project(FINAL).docx)</p>
<p> The code of the server can be found inside the /server directory of the repo (https://github.com/rafnocerino/Secure_4_inArow/tree/master/server)</p>

#### Authors 
<ul>
<li> Lorenzoni Dario  -  </li>
<li> Nocerino Raffaele - rafnocerino96@gmail.com</li>
<li> Xefraj Riccardo   - riccardoxefraj@yahoo.it</li>
</ul>
