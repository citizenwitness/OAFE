![enter image description here](https://s15.postimg.org/r78hct68b/OAFELOGO1.png)  


----------


**Open Advanced Forensic Examiner (OAFE) (TM)**
-----------------------------------------

 Prerequisites
-------------

**Hardware**

16GB RAM
250GB + HDD (SSD or RAID preferred)
4 Core processor
2 Network interface cards

Installation
------------

Obtain an Ubuntu 16.04.2 LTS x64 Desktop USB install drive (or create one using Rufus (windows) and downloading the latest ISO from the Ubuntu website).

Boot to USB drive

 1. Install Ubuntu Desktop 16.04.02 LTS x64 with a default username of oafe.  This is important unless you want to alter the script for a different user.
 2.  Update and upgrade the software packages on your Ubuntu install.
 3. From a terminal window, install the following (you may want to update your profile preferences in terminal to not limit scrollback..this is helpful to troubleshoot). Edit -> Profile Preferences -> Scrolling -> Uncheck the box that says limit scrollback:
 4. In the terminal window you have opened, type `sudo apt-get install git nginx-full` and hit Enter.
 5. Clone the OAFE repository. From a terminal: `git clone https://github.com/rebaker501/OAFE.git`
 6. Change to the directory created during the git clone (cd OAFE most likely) and invoke the bootstrap. Type `sudo bash ./install_OAFE_16.04.sh -i -s -y`
 7. The first time the script stops it will ask you to enter some information for the nginx ssl certificate. You can enter any information you would like in the certificate fields.
 8. When the script stops again, it will be prompting you for a password for the oafe user for nginx.  This will allow access to the reverse proxied Kibana instance.
 9. The next time the script pauses is to install moloch, you should select whatever interface you'd like to use as the network monitoring interface, type no to install the demo elasticsearch server, when asked for the default elasticsearch location, make sure to type out http://localhost:9200 or the install will fail.  Choose a password for the admin account for the Moloch web interface.
 10. When the script is complete, reboot. 
 11. Once the newly built OAFE is back up an running, open a command prompt.  CD to /opt/oafe/grr.  From that directory run `sudo bash ./install_google_rapid_response.sh` 
 12. Tailor the GRR install for your needs.
 13. When the install is complete, add an oafe user for GRR.  First run `sudo grr_config_updater add_user INSERTYOURUSERNAMEHERE`.  
 14. Add admin access by issuing the following `sudo grr_config_updater update_user oafe --add_labels admin,user`
 15. Add Moloch user.  From a terminal cd to /data/moloch/viewer.  Issue the following command `sudo node addUser.js PICKAUSERNAME "ADMIN User" PICKAPASSWORD -admin`.
