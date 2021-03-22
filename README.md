# E-ARK IP Viewer

The E-ARK ipviewer is a software for viewing E-ARK information packages. It reads packaged container files as input and 
then visualizes structure, metadata, and provenance information of the information package.

The purpose of the IP Viewer is to demonstrate the use of metadata recommended by E-ARK standards to:

* represent the structure of the information package using METS,
* visualise which metadata is stored within the package, 
* and providing a possibility to add specific modules for the visualisation of specific metadata (like EAD, DC, …) the 
  provenance information using PREMIS.

## Install

Requires: Python >=3.7, <4.0.0 

1. Checkout project

       git clone https://github.com/E-ARK-Software/ipviewer.git
        
    Change to earkweb directory:

       cd ipviewer
       
2. Copy the settings template file and adapt parameters if needed:

        cp settings/settings.cfg.default settings/settings.cfg
    
3. Create virtual environment (python)

       virtualenv -p python3 venv

4. Install additional python packages:

       pip3 install -r requirements.txt
       
5. Create a user (user name, email, password, super user status) using the Django function:

       python manage.py createsuperuser
       
6. Create database tables

        python manage.py makemigrations
        python manage.py makemigrations ipviewer
        python manage.py migrate
        
7. Verify if the user data directory exists and is writable (parameter `ip_data_path` in `settings/settings.cfg`)
       
## Run

1. Start the application:

        python manage.py runserver 0.0.0.0:8001
    
2. Run Huey task queue

        python3 manage.py run_huey
    
3. Login with username/password defined in step 5 of the installation.

4. In the test/resources/ directory, there are information package examples which can be uploaded, for example:

       urn+uuid+46f99745-2f60-4849-9406-d3fe40f67a67.tar
