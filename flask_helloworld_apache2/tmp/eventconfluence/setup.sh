

mkdir /var/log/istiopoc
chown -R www-data /var/log/istiopoc
mkdir /var/data
chown -R www-data /var/data

cp *.py /var/www/flask
cp *.conf /var/www/flask

