---
layout: article

title: Anghami's Android app and API security
tags: Security
pageview: true
article_header:
  type: cover
  align: center
  image:
    src: /assets/anghami-logo-colored.png

---

## Introduction

Anghami is the first and biggest legal music streaming platform and digital distribution company in the Arab world.

And after playing around with their android app, i found some interesting methods that the app used to prevent users from recompiling/editing the apk file.
And here's what i found:

# Apk signature check

After i decompiled/recompiled their latest apk with [Apktool](https://ibotpeaches.github.io/Apktool/) and signed it, it showed me a "This app isn't official, please install the latest version from play store" message after it got installed.
So i reversed the apk code with [Jadx](https://github.com/skylot/jadx) and found that they used a classic signature check method with a little touch:

```java
public static String m26492a(String str, byte[] bArr) {
        try {
            Signature[] signatureArr = AnghamiApplication.m9158h().getPackageManager().getPackageInfo(AnghamiApplication.m9158h().getPackageName(), 64).signatures;
            if (signatureArr.length <= 0) {
                return "";
            }
            Signature signature = signatureArr[0];
            MessageDigest instance = MessageDigest.getInstance("SHA");
            instance.update(signature.toByteArray());
            MessageDigest instance2 = MessageDigest.getInstance(Constants.SHA256);
            String str2 = new String(Base64.encode(instance.digest(), 0)) + str;
            instance2.update(str2.getBytes("iso-8859-1"), 0, str2.length());
            instance2.update(bArr);
            return m26497b(instance2.digest());
        } catch (Exception e) {
            C6283c.m20676a("Utils: Array  Exception:", e);
            return "";
        }
    }
```

And what this function simply do is:

1. Get the app signature with `packageManager`

2. Update the signature's byte array with a byte array that sent from server

3. Return the result to the server and check if it's correct

Also they use this method for Almost any API call.

So passing that method wasn't tough:

```java
    public static String m26492a(String str, byte[] bArr) {
        try {         
            MessageDigest instance = MessageDigest.getInstance("SHA");
            instance.update(getAppSign());
            MessageDigest instance2 = MessageDigest.getInstance(Constants.SHA256);
            String str2 = new String(Base64.encode(instance.digest(), 0)) + str;
            instance2.update(str2.getBytes("iso-8859-1"), 0, str2.length());
            instance2.update(bArr);
            return m26497b(instance2.digest());
        } catch (Exception e) {
            C6283c.m20676a("Utils: Array  Exception:", e);
            return "";
        }
    }

    public static byte[] getAppSign() {
        //Note: This is not the full signature byte array
        return new byte[]{48, -126, 3, 74, 48, -126, 2, 50, -96, 3, 2, 1, 2, 2, 4, 80, Byte.MAX_VALUE, -21};
    }
```

Just replace the `packageManager`signature call with hardcoded byte array signature (Logged with `packageManager`call externally).

And that was it, Now you can edit the apk, sign it and install it with everything working!

# Enabling Plus features

![](/assets/anghami-ss-1.jpg){:width="284px" height="512px"}

So after passing the signature check, enabling plus features wasn't that tough (Even for Downloads).
For example, Anghami added a feature called "Offline Mixtape" where you can download a generated list for free, So it enable downloading for all songs you just need to mark every song as "Offline Mixtape" song (Yes there's no verification for download which I'll talk about in the next section).

# Downloads Verification

![](/assets/anghami-downloader.gif){:width="284px" height="512px"}

And after i found that free users can download i was wondering how their downloads requests looks like, So i did some digging and here's what i found:

### Downloads Request

Downloads requests looked like this:

```
POST /rest/v1/GETDownload.view?output=jsonhp&sid=i7%3Affhdddig%3A27os09q2n4noos93%3Aececddecdkcdcj%3ART%3Afe%3Ara%3An5.4.44%3A104%3A%3An5.4.44%3A0%3Ann%3Ap8s373156n h2 
Host: api.anghami.com 
user-agent: Anghami Android 5.4.44 / V 10 (54044) Google store 
x-angh-ts: 1605922603 
x-angh-encpayload: 4 
x-socket-id: az7-1q--kmDxIdYzDjqB 
x-angh-udid: 27bf09d2a4abbf93 
x-angh-rgsig: 5a1b26f5990ba3b6d7f3e37b486d2023 
x-angh-app-rgsig: 2780d2df9f3e60dbeea51626dc30a6b6263fce9362dad1483f5fd0b9d9460d3b 
x-angh-app-salt: 49cc7b68-b291-493e-909f-d5064228c928 
content-type: application/x-www-form-urlencoded; charset=utf-8 
content-length: 96 
accept-encoding: gzip 

##�́� � ��%�C
u ��� E�Ex{s�� ]}+%������s� �{��Q ��  �����5� <�� �y���\|�V ]d)��
E���  x �-�If'
```

Just a bunch of generated strings in headers with some data fetched from server and an Encrypted, GZipped body.

And when you decrypt the body it will like this:

`HQ=196&intent=download&fileid=835805` 

So if you're wondering how this headers are generated and how the body is encrypted, Here's what's happening behind the scene:

```java
class AnghInterceptor implements Interceptor {
    //Android device id.
    private static final String androidId = "27bf09d2a4gdsthx";
    private static final Charset f15353e = Charset.forName("UTF-8");
    private Random f15359a = new SecureRandom();
    private static final byte[] f15354f = new byte[0];
    //Again, This is not the full signature byte array.
    private static final byte[] signByteArr = {48, -126, 3, 74, 48, -126, 2, 50, -96, 3, 2, 1, 2, 2, 4, 80, Byte.MAX_VALUE, -21};

    @NotNull
    @Override
    public Response intercept(@NotNull Chain chain) throws IOException {
        HttpUrl mVar;
        byte[] bArr;
        byte[] bArr2;
        RequestBody tVar;
        String str;
        ResponseBody a;
        Request request = chain.request();
        List<String> j = request.url().pathSegments();
        String str2 = !j.isEmpty() ? j.get(j.size() - 1) : null;
        //Logged from the app with a free user logged in
        String fetchSessionId = "i7:kdcgiekl:27os09q2n4noos93:ececddehdlhgeg:FL:d:ra:n5.4.44:530::n5.4.44:0:na:2n5762s256";
        Request.Builder f = request.newBuilder();
        String e = request.method();
        RequestBody a2 = request.body();
        long currentTimeMillis = System.currentTimeMillis() / 1000;
        HttpUrl.Builder i = request.url().newBuilder();
        i.addQueryParameter("sid", fetchSessionId);
        mVar = i.build();
        Buffer cVar = new Buffer();
        a2.writeTo(cVar);
        bArr = cVar.readByteArray();
        a2 = RequestBody.create(bArr, a2.contentType());
        Buffer cVar2 = new Buffer();
        a2.writeTo(cVar2);
        byte[] readByteArray = cVar2.readByteArray();
        cVar2.close();
        bArr2 = "e0de83542e294fefb0860660eb228f56".getBytes();
        bArr = m20615b(Gzip.gZip(readByteArray), "b03040d7cc781684584220da685e3a17".getBytes());
        tVar = RequestBody.create(bArr, a2.contentType());
        f.method(e, tVar);
        f.addHeader("User-Agent", "Anghami Android 5.4.44 / V 10 (54044) Google store");
        f.addHeader("X-ANGH-TS", String.valueOf(currentTimeMillis));
        f.addHeader("X-ANGH-ENCPAYLOAD", "4");
        //Also logged from the app
        String e2 = "ajauhTLV9kRomkyDKB9_";
        f.addHeader("X-Socket-ID", e2);
        String b2 = androidId;
        f.addHeader("X-ANGH-UDID", b2);
        String mVar2 = mVar.toString();
        str = mVar2.substring(mVar2.indexOf("/rest/")).trim();
        byte[] bytes = str.getBytes();
        bytes = m26223b(bytes, bArr);
        m26494a(f, bytes);
        String g = mVar.host();
        if ("api.anghami.com".equals(g)) {
            HttpUrl.Builder i2 = mVar.newBuilder();
            i2.host(g);
            mVar = i2.build();
        }
        f.url(mVar);
        Request a3 = f.build();
        Response proceed = chain.proceed(a3);
        if (!((a = proceed.body()) == null)){
            BufferedSource f2 = a.source();
            f2.request(Long.MAX_VALUE);
            try {
                ResponseBody a4 = ResponseBody.create(Gzip.unzip(m20611a(f2.buffer().readByteArray(), bArr2)), MediaType.parse("application/json"));
                Response.Builder j2 = proceed.newBuilder();
                j2.body(a4);
                proceed = j2.build();
            }catch (IOException e3){
                Log.e("anghami", "Error decrypting. Response: " + proceed);
                throw e3;
            }
        }

        return proceed;

    }
    private byte[] m20611a(byte[] bArr, byte[] bArr2) throws IOException {
        int i = 0;
        int i2 = 0;
        while (i < 2 && i2 < bArr.length) {
            i = bArr[i2] == 35 ? i + 1 : 0;
            i2++;
        }
        if (i == 2) {
            byte[] bArr3 = new byte[8];
            byte[] bArr4 = new byte[12];
            if (bArr.length >= bArr3.length + bArr4.length + i2) {
                System.arraycopy(bArr, i2, bArr3, 0, bArr3.length);
                int length = i2 + bArr3.length;
                System.arraycopy(bArr, length, bArr4, 0, bArr4.length);
                int length2 = length + bArr4.length;
                int length3 = bArr.length - length2;
                byte[] bArr5 = new byte[length3];
                System.arraycopy(bArr, length2, bArr5, 0, length3);
                byte[] bArr6 = new byte[(length3 + 1024)];
                int[] iArr = new int[1];
                if (NaCl.sodium().crypto_aead_chacha20poly1305_decrypt(bArr6, iArr, f15354f, bArr5, length3, bArr4, bArr4.length, bArr3, bArr2) >= 0) {
                    byte[] bArr7 = new byte[iArr[0]];
                    System.arraycopy(bArr6, 0, bArr7, 0, iArr[0]);
                    return bArr7;
                }
                throw new IOException("Decode failed:\n");
            }
            throw new IOException("Payload too short: ");
        }
        throw new IOException("Failed to find payload\n");
    }
    private static void m26494a(Request.Builder aVar, byte[] bArr) {
        String uuid = UUID.randomUUID().toString();
        aVar.addHeader("X-ANGH-RGSIG", m26493a(bArr));
        aVar.addHeader("X-ANGH-APP-RGSIG", m26492a(uuid, bArr));
        aVar.addHeader("X-ANGH-APP-SALT", uuid);
    }
    public static String m26492a(String str, byte[] bArr) {
        try {

            MessageDigest instance = MessageDigest.getInstance("SHA");
            instance.update(signByteArr);
            MessageDigest instance2 = MessageDigest.getInstance("SHA-256");
            String str2 = new String(Base64.encode(instance.digest(), 0)) + str;
            instance2.update(str2.getBytes("iso-8859-1"), 0, str2.length());
            instance2.update(bArr);
            return m26497b(instance2.digest());
        } catch (Exception e) {
            return "";
        }
    }
    public static String m26493a(byte[] bArr) {
        try {
            MessageDigest instance = MessageDigest.getInstance("SHA-1");
            instance.update(bArr);
            instance.update("07v8Q7baW2".getBytes());
            return m26497b(instance.digest()).substring(0, 32);
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }
    private static String m26497b(byte[] bArr) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bArr) {
            int i = (b >>> 4) & 15;
            int i2 = 0;
            while (true) {
                sb.append((char) ((i < 0 || i > 9) ? (i - 10) + 97 : i + 48));
                i = b & 15;
                int i3 = i2 + 1;
                if (i2 >= 1) {
                    break;
                }
                i2 = i3;
            }
        }
        return sb.toString();
    }
    private static byte[] m26223b(byte[] bArr, byte[] bArr2) {
        byte[] bArr3 = new byte[(bArr.length + bArr2.length)];
        System.arraycopy(bArr, 0, bArr3, 0, bArr.length);
        System.arraycopy(bArr2, 0, bArr3, bArr.length, bArr2.length);
        return bArr3;
    }
    private byte[] m20615b(byte[] bArr, byte[] bArr2) {
        int length = bArr.length;
        byte[] bArr3 = new byte[(length + 1024)];
        byte[] bArr4 = new byte[8];
        byte[] bArr5 = new byte[12];
        this.f15359a.nextBytes(bArr4);
        this.f15359a.nextBytes(bArr5);
        int[] iArr = new int[1];
        NaCl.sodium().crypto_aead_chacha20poly1305_encrypt(bArr3, iArr, bArr, length, bArr5, bArr5.length, f15354f, bArr4, bArr2);
        byte[] bArr6 = new byte[(bArr4.length + 2 + bArr5.length + iArr[0])];
        bArr6[0] = 35;
        bArr6[1] = 35;
        System.arraycopy(bArr4, 0, bArr6, 2, bArr4.length);
        int length2 = 2 + bArr4.length;
        System.arraycopy(bArr5, 0, bArr6, length2, bArr5.length);
        System.arraycopy(bArr3, 0, bArr6, length2 + bArr5.length, iArr[0]);
        return bArr6;
    }
```

Long story short, It's similar to the verification from first section.
The app adds a lot of things to the request body's byte array like current time in milliseconds, some fetched parameters from the server, etc.                                    
Then it encrypt it with "AEAD" and Gzip it then sends it to server for verification.          
And as i said there's no verification for if the user is a plus user or not, It just responds to your request (Even if it's outside the app as the demo above).

And the response looks like this:

```json
{
  "angtime": 1606334724,
  "status": "ok",
  "version": "1.0.0",
  "_request_id": "2886747652_656b72341598c817feef697bc1af554c",
  "uint": 2631333181,
  "requestedfileid": "24218943",
  "requestedvideoid": null,
  "atags": "newly_churned:1,reduced_limits:1,SongAbuse:30,ArtistAbuse:30",
  "__dcost": "0.786302102054839",
  "extras": "eyJyZXF1ZXN0dHlwZWlkIjo4LCJyZXF1ZXN0dHlwZSI6IkdFVGRvd25sb2FkIiwicmVxdWVzdG9uZGVtYW5kIjowfQ==",
  "responsetype": "GETdownload",
  "sections": [
    {
      "type": "song",
      "group": "download",
      "count": 1,
      "playmode": "list",
      "sectionid": 1,
      "initialNumItems": 1,
      "displaytype": "carousel",
      "data": [
        {
          "nofollow": false,
          "id": "24218943",
          "title": "Die Trying",
          "album": "Michl",
          "albumID": "2597502",
          "artist": "Michl",
          "artistID": "1790308",
          "track": "4",
          "year": "2016",
          "duration": "208.00",
          "coverArt": "3794535",
          "ArtistArt": "1128277980",
          "allowoffline": 1,
          "genre": "R&B/Soul",
          "AlbumArt": "3794535",
          "keywords": [
            "Die Trying",
            "Michl",
            "Michl"
          ],
          "languageid": 2,
          "bitrates": "24,256",
          "hexcolor": "#a1a292",
          "nouservideo": "1",
          "cleardetails": 1,
          "bitrate": 64,
          "size": "1698277",
          "releasedate": "2016-05-10",
          "explicit": "0",
          "extras": "eyJyZXF1ZXN0dHlwZWlkIjo4LCJyZXF1ZXN0dHlwZSI6IkdFVGRvd25sb2FkIiwicmVxdWVzdG9uZGVtYW5kIjowLCJzZWN0aW9uIjoiZG93bmxvYWQifQ==",
          "lyrics": "true",
          "is_original": 1,
          "vibes": [
            59,
            1024
          ],
          "location": "https://anghamiaudiospdy.akamaized.net/mp43/859717873601_01_4.m4a?anghakamitoken=st=1606334604~exp=1606335084~acl=*~hmac=c8b927b0b340e499cfc35aba8e91cbd28bb69c7926013659cb81cd358687ec58",
          "debugurl": "http://anghamiaudiospdy.akamaized.net.t1.re",
          "debugurldata": "http://anghamiaudiospdy.akamaized.net.t1.re",
          "hash": "67361a7cff06ecffb854624c1fd49ce5",
          "plays": "602142",
          "likes": "20281",
          "progress": 0,
          "index": 0
        }
      ],
      "index": 0
    }
  ]
}
```

And as it showed in the demo you can get the song file by going to the "location" link.

# Summary

Anghami's security looks good from outside, But developers wrote it as if it's no one is going to dig in their code, As above requests body is encrypted and you can't edit/modify the app because of their signature check, But once you pass that, You can pass everything else very easily. 
