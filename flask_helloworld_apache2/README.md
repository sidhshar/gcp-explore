# Flask Hello World 

### Hosted in GCP

sudo apt-get update

sudo apt-get install python-pip

sudo apt-get install git

sudo apt-get install apache2

sudo apt-get install libapache2-mod-wsgi

sudo a2enmod wsgi

sudo su

pip install flask

exit

screen

cd

git clone https://github.com/sidhshar/gcp-explore.git

cd gcp-explore/flask_helloworld_apache2

sudo mkdir /var/www/flask

sudo cp webtool.* /var/www/flask/

sudo cp 000-default.conf /etc/apache2/sites-available/

sudo service apache2 restart

systemctl status apache2.service

# Access and Error Logs
tail -f /var/log/apache2/error.log

tail -f /var/log/apache2/access.log
