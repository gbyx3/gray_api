# gray_api
Generic API to interact Graylog with other centrall systems  


## Setup

1. ) Import the graylog extractors, or alter the code to work your setup  
```
# sed -i 's/ssh_invalid_user_ip/<YOUR FIELD>//g' forti_api.py
```
  
2. ) Create a Graylog HTTP Notification and point it to your application
```
# http://127.0.0.1:8080/forti_api/v1/redis_blocklist
```

3. ) Create the event definition,  
I only set the search query to fetch messages witch contains my extractor field  
```
Search Query: _exists_:ssh_invalid_user
```
and set the notification to that you created in the previous step  


# Disclaimer


# Example:
Linux server authlog -> Graylog Alert -> gray_api -> IP Block list
