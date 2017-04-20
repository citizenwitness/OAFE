![enter image description here](https://s15.postimg.org/r78hct68b/OAFELOGO1.png)  


----------


**Optum Advanced Field Examiner (OAFE) (TM)**
-----------------------------------------

 Prerequisites
-------------

**For OAFE installs at Optum:**

iLo configured (F9 System Configuration on HP DL380)
emphasized text
RAID Array configured (Raid 5 - max amount of space available) (F9 System Configuration on HP DL380)

*NOTE: The OAFE script can be run on other hardware or VMs, but it will have serious performance problems under load. We use VMs and desktops for testing.*

Installation
------------

Obtain an Ubuntu 16.04.2 LTS USB install drive (or create one using Rufus (windows) and downloading the latest ISO from the Ubuntu website).

Boot to USB drive (F11 Boot menu on the HP DL380)

 1. Choose Try Ubuntu before installing on the boot menu.
 2. When the Ubuntu desktop appears, at the top of the screen, right corner (wifi icon), set your IP address, subnet, gateway, and DNS servers that the AE has given you for the management interface. NOTE: You will need to ensure that they have given this IP rights to access the internet directly with no proxy and that the IP can be accessed from VNC (tcp 5900) and ssh (tcp 22) from the VPN (if they have one) and the internal network.
 3. Verify internet connection by opening firefox and going to a couple of sites. IF YOU DO NOT GET INTERNET, YOU WILL NEED TO WORK WITH ONSITE STAFF TO FIX THE PROBLEM BEFORE PROCEEDING ANY FURTHER.
 4. Once the Internet connection is verified, double click the install Ubuntu icon on the desktop.
 5. When installer launches, please check install updates while installing and install additional software. IF THE INSTALL UPDATES BUTTON IS GREYED OUT, YOU DO NOT HAVE AN INTERNET CONNECTION. WORK WITH ONSITE PERSONNEL TO REMEDY THE ISSUE. BUTTON WILL UN-GREY WHEN INTERNET IS RESTORED.
 6. For all sites, except AMIL, use entire drive for ubuntu and erase everything.
 7. IMPORTANT!!! TIMEZONE MUST BE SET TO NEW YORK EST.
 8. Keyboard layout is US
 9. The username should be named oafe password provided by CFI personnel (This needs to be set during install). It is absolutely imperative to name the user oafe and the username oafe. The computer name should be acquiredentityname or oafeaenamedatacentername (please use lowercase and no special characters or spaces).  Example oaferiverside or oafeamilembratel.
 10. Complete the install and reboot.
 11. From the search button in Ubuntu, find Software Updater and run all updates. Reboot (if required). Repeat this procedure until there are no updates.
 12. From a terminal window, install the following (you may want to update your profile preferences in terminal to not limit scrollback..this is helpful to troubleshoot). Edit -> Profile Preferences -> Scrolling -> Uncheck the box that says limit scrollback:
 13. In the terminal window you have opened, type `sudo apt-get install git nginx-full` and hit Enter.
 15. Clone the OAFE repository to the /opt/oafe/ directory. From a terminal: `git clone https://github.com/rebaker501/oafeubuntu.git` (You will need the username and password for this)
 16. Change to the directory created during the git clone (cd oafeubuntu or cd ~/oafeubuntu) and invoke the bootstrap. Type `sudo bash ./install_OAFE_16.04.sh -i -s -y` (You can add a -d to the end if you'd like to download the analysis VMs. This will take a while (~7GB) and the systems will need to be re-activated/licensed. The office software and the OS will require this activation. 
 17. During the execution of the script, it will ask you for your github login to get to this code.
 18. The first time the script stops it will ask you to enter some information for the nginx install, leave everything default by just hitting enter until you are prompted to enter a new password, use the standard oafe password for this.
 19. The next time the script pauses to ask you for information is during the webmin install, please just hit enter for all the defaults except when it comes to using ssl, please hit y for yes.
 20. The next time the script pauses is to install moloch, you should select eno1 as the interface, type no to install the demo elasticsearch server, when asked for the default elasticsearch location, make sure to type out http://localhost:9200 or the install will fail.  When asked for a password, use the oafe password.
 21. When the script is complete, reboot. 
 22. Once the newly built OAFE is back up an running, open a command prompt.  CD to /opt/oafe/grr.  From that directory run `sudo bash ./install_google_rapid_response.sh` 
 23. Accept all of the defaults for the install and use the oafe password when prompted for a password for admin.
 24. When the install is complete, add an oafe user for GRR.  First run `sudo grr_config_updater add_user oafe` and use the oafe password for that user.  Add admin access by issuing the following `sudo grr_config_updater update_user oafe --add_labels admin,user`
 25. If you'd like to give the AE access to the binaries, create them a user.  Same method.  Issue the command `sudo grr_config_updater add_user aename` Replace aename with something related to their business name.  Make up a password for that account and give them the credentials and the location of the login page on their network. Example http://mgmt.ip:8000 Replace mgmt.ip with the internal IP they AE provided to you.
 26. Add Moloch user.  From a terminal cd to /data/moloch/viewer.  Issue the following command `sudo node addUser.js oafe "OAFE ADMIN User" oafepassword -admin` Replace oafepassword with the actual oafe user password.

	
Extras:  Finally, once you confirm your services are running correctly we highly suggest you use the Ubuntu firewall. There is a script in the folder titled `/opt/oafe/oafeubuntu/conf/Ubuntufirewall` called `ufwruleenable.sh` that you can use to lock down everything. All services labeled in the wiki ports page show which service ports will be available externally. You may need to chmod the script before you can run it. Run it by changing into the directory then typing `./ufwruleenable.sh`
