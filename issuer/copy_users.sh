sudo docker exec -i issuer-db-1 psql -U postgres -d upc_users -c "\copy users(username) FROM STDIN DELIMITER ',' CSV HEADER;" < ./users.csv
