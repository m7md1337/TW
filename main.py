import json
import random
import requests
import hashlib
import hmac
import tqdm
import urllib,datetime
from retrying import retry
import time as timm
import base64

alltweets = {}
selecttweets = []

def generate_random_key(length):
    xx = "0123456789ABCDEF"
    return ''.join(random.choice(xx) for _ in range(length))

def randomUUID():
    UUID8 = generate_random_key(8)
    UUID4 = generate_random_key(4)
    UUID4_2 = generate_random_key(3)
    UUID4_3 = generate_random_key(4)
    UUID12 = generate_random_key(12)
    randomUUID = "{}-{}-4{}-{}-{}".format(UUID8,UUID4,UUID4_2,UUID4_3,UUID12)
    return randomUUID

def GuestToken():
    url = 'https://api.twitter.com/1.1/guest/activate.json'
    headers = {'Host': 'api.twitter.com',
                'X-Twitter-Client-DeviceID': randomUUID(),
                'Authorization':'Bearer {}'.format('AAAAAAAAAAAAAAAAAAAAAAj4AQAAAAAAPraK64zCZ9CSzdLesbE7LB%2Bw4uE%3DVJQREvQNCZJNiz3rHO7lOXlkVOQkzzdsgu6wWgcazdMUaGoUGm'),
                'X-Client-UUID': randomUUID()}

    get_guest_token_ = requests.post(url, headers=headers)
    json_guest_token = json.loads(get_guest_token_.content)
    guest_token=json_guest_token['guest_token']
    return guest_token


def sign_request(oauth_token_secret,raw):
    # key = b"CONSUMER_SECRET&oauth_token_secret" #
    key = b"GgDYlkSvaPxGxC4X8liwpUoqKwwr3lCADbz8A7ADU&"+oauth_token_secret.encode()

    hashed = hmac.new(key, raw, hashlib.sha1)

    # The signature
    return base64.b64encode(hashed.digest())



def login(Username,Password):
    url = 'https://api.twitter.com/auth/1/xauth_password.json'
    headers = {'User-Agent':'Twitter-HEXXXX/8.27.1 iOS/13.3 (Apple;hex,6;;;;;1;2017)',
               'Host': 'api.twitter.com' ,
               'X-Twitter-Client-DeviceID':randomUUID(),
               'Authorization':'Bearer {}'.format('AAAAAAAAAAAAAAAAAAAAAAj4AQAAAAAAPraK64zCZ9CSzdLesbE7LB%2Bw4uE%3DVJQREvQNCZJNiz3rHO7lOXlkVOQkzzdsgu6wWgcazdMUaGoUGm'),
               'X-Client-UUID':randomUUID(),
               'X-Guest-Token':GuestToken(),
               'Content-Type':'application/x-www-form-urlencoded'}
    data  = 'send_error_codes=1&x_auth_identifier={}&x_auth_login_verification=true&x_auth_password={}'.format(Username,Password)
    login = requests.post(url , data=data ,headers=headers)
    return login

@retry(stop_max_attempt_number=10)
def DestoyTweets(oauth_token_secret,oauth_token,ids):
    time1 = str(datetime.datetime.now().timestamp()).split(".")[0]
    databeforeEnc = "POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fdestroy%2F{}.json&oauth_consumer_key%3DIQKbtAYlXLripLGPWd0HUA%26oauth_nonce%3D133333333337%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D{}%26oauth_token%3D{}%26oauth_version%3D1.0".format(
        ids,time1, oauth_token)
    sig = sign_request(oauth_token_secret,databeforeEnc.encode()).decode().replace("=", "%3D")
    headers = {'Connection': 'close', 'X-Twitter-Client-Language': 'en',
               'Content-Type': 'application/x-www-form-urlencoded', 'Host': 'api.twitter.com',
               'Authorization': 'OAuth oauth_signature="{}", oauth_nonce="133333333337", oauth_timestamp="{}", oauth_consumer_key="IQKbtAYlXLripLGPWd0HUA", oauth_token="{}", oauth_version="1.0", oauth_signature_method="HMAC-SHA1"'.format(
                   sig,time1, oauth_token)}
    req1 = requests.post("https://api.twitter.com/1.1/statuses/destroy/"+ids+".json", headers=headers)
    if req1.status_code == 200:
        tqdm.tqdm.write("successfully delete the tweet",end='\r')
    elif "Could not authenticate you." in req1.text:
        raise ValueError("raise error to retry send the requests")
    else:
        tqdm.tqdm.write("error")
        tqdm.tqdm.write(req1.text,end='\r')

@retry(stop_max_attempt_number=10)
def takefirti(oauth_token_secret,oauth_token):
    time1 = str(datetime.datetime.now().timestamp()).split(".")[0]
    databeforeEnc = "GET&https%3A%2F%2Fapi.twitter.com%2F1.1%2Ftimeline%2Fuser.json&count%3D40%26include_my_retweet%3D1%26include_rts%3Dtrue%26include_tweet_replies%3Dtrue%26include_user_entities%3Dtrue%26oauth_consumer_key%3DIQKbtAYlXLripLGPWd0HUA%26oauth_nonce%3D133333333337%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D{}%26oauth_token%3D{}%26oauth_version%3D1.0".format(
        time1,oauth_token)

    sig = sign_request(oauth_token_secret,databeforeEnc.encode()).decode().replace("=", "%3D")
    headers = {'Connection': 'close', 'X-Twitter-Client-Language': 'en',
                   'Content-Type': 'application/x-www-form-urlencoded', 'Host': 'api.twitter.com',
                   'Authorization': 'OAuth oauth_signature="{}", oauth_nonce="133333333337", oauth_timestamp="{}", oauth_consumer_key="IQKbtAYlXLripLGPWd0HUA", oauth_token="{}", oauth_version="1.0", oauth_signature_method="HMAC-SHA1"'.format(
                       sig,time1, oauth_token)}

    req1 = requests.get("https://api.twitter.com/1.1/timeline/user.json?count=40&include_my_retweet=1&include_rts=true&include_tweet_replies=true&include_user_entities=true", headers=headers)
    if json.loads(req1.text)["twitter_objects"]['tweets'] != {}:
        for xx in json.loads(req1.text)["twitter_objects"]["tweets"]:
            alltweets[xx] = timm.mktime(datetime.datetime.strptime(json.loads(req1.text)["twitter_objects"]["tweets"][xx]["created_at"], "%a %b %d %X %z %Y").timetuple())
        nextone(json.loads(req1.text)["response"]["cursor"]["bottom"],oauth_token_secret,oauth_token)


@retry(stop_max_attempt_number=10)
def nextone(id,oauth_token_secret,oauth_token):

    time = str(datetime.datetime.now().timestamp()).split(".")[0]
    databeforeEnc = "GET&https%3A%2F%2Fapi.twitter.com%2F1.1%2Ftimeline%2Fuser.json&count%3D40%26down_cursor%3D{}%26include_my_retweet%3D1%26include_rts%3Dtrue%26include_tweet_replies%3Dtrue%26include_user_entities%3Dtrue%26oauth_consumer_key%3DIQKbtAYlXLripLGPWd0HUA%26oauth_nonce%3D133333333337%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D{}%26oauth_token%3D{}%26oauth_version%3D1.0".format(
        id,time,oauth_token)

    sig = sign_request(oauth_token_secret,databeforeEnc.encode()).decode().replace("=", "%3D")
    headers = {'Connection': 'close', 'X-Twitter-Client-Language': 'en',
               'Content-Type': 'application/x-www-form-urlencoded', 'Host': 'api.twitter.com',
               'Authorization': 'OAuth oauth_signature="{}", oauth_nonce="133333333337", oauth_timestamp="{}", oauth_consumer_key="IQKbtAYlXLripLGPWd0HUA", oauth_token="{}", oauth_version="1.0", oauth_signature_method="HMAC-SHA1"'.format(
                   sig, time, oauth_token)}

    req1 = requests.get(
        "https://api.twitter.com/1.1/timeline/user.json?down_cursor={}&count=40&include_my_retweet=1&include_rts=true&include_tweet_replies=true&include_user_entities=true".format(id),
        headers=headers)

    id = json.loads(req1.text)["response"]["cursor"]["bottom"]
    if json.loads(req1.text)["twitter_objects"]['tweets'] != {}:
        for xx in json.loads(req1.text)["twitter_objects"]["tweets"]:
            alltweets[xx] = timm.mktime(datetime.datetime.strptime(json.loads(req1.text)["twitter_objects"]["tweets"][xx]["created_at"],"%a %b %d %X %z %Y").timetuple())
        print("info : still processing moving to next one page each page limit tweets are 40 ")
        nextone(id,oauth_token_secret,oauth_token)

def main():
    user = input("enter username: ")
    password = input("enter passowrd: ")
    trylogin = login(user,password)
    if trylogin.status_code == 401:
        print("are you sure about login information ?")
    elif trylogin.status_code == 200:
        try:
            jsondata = json.loads(trylogin.content)
            auth_token = jsondata['oauth_token']
            oauth_token_secret = jsondata['oauth_token_secret']
            takefirti(oauth_token_secret, auth_token)
            if alltweets:
                sortweets = dict(sorted(alltweets.items(), key=lambda item: item[1], reverse=True))
                print("count of tweets is :", len(sortweets), " , your tweets date from ",
                      datetime.datetime.fromtimestamp(sortweets[max(sortweets, key=sortweets.get)]), "-> ",
                      datetime.datetime.fromtimestamp(sortweets[min(sortweets, key=sortweets.get)]))

                while True:
                    print(
                        "\nchose the options \n1 for delete all tweets \n2 for delete any tweets between two date ex : 2016-11-15 2011-10-07 \n3 for delete any tweets before the date   ex : 2016-11-15  ")
                    ii = input("enter the number: ")
                    if ii == "1":
                        for xx in sortweets.keys():
                            selecttweets.append(xx)
                        break
                    elif ii == "2":
                        dates = input("enter the dates (ex 2016-11-15 2011-10-07 space between two date) : ")
                        two = sorted([timm.mktime(datetime.datetime.strptime(xx, "%Y-%m-%d").timetuple()) for xx in
                                      dates.split(" ")])
                        for xx in sortweets.keys():
                            if two[0] <= sortweets[xx] <= two[1]:
                                selecttweets.append(xx)
                        break
                    elif ii == "3":
                        dates = input("enter the dates (ex. 2016-11-15) : ")
                        timestamp = timm.mktime(datetime.datetime.strptime(dates, "%Y-%m-%d").timetuple())
                        for xx in sortweets.keys():
                            if timestamp > sortweets[xx]:
                                selecttweets.append(xx)
                        for xx in selecttweets:
                            print(datetime.datetime.fromtimestamp(sortweets[xx]))
                        break

                    else:
                        print("error enter valid option ")

                for ids in tqdm.tqdm(selecttweets):
                    DestoyTweets(oauth_token_secret,auth_token,ids)
                print("cool all tweets select are deleted")
            else:
                print("[Info] No tweet found")
        except Exception as dd:
            print("oops something wrong error:  "+str(dd))

if __name__ == '__main__':
    main()
