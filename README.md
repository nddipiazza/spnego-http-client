# Example of using Apache Components HTTP Client with Spnego Preemptive Negogiate Authorization

There is already an example of using SPNEGO with Apache HttpComponents HTTP Client here https://github.com/jumarko/kerberos-auth-example/blob/master/src/main/java/net/curiousprogrammer/auth/kerberos/example/KerberosAuthExample.java

But using the AuthScheme.SPNEGO has two issues:

* It forces you to use the default GSS login security context entry name. So if your JVM needs to support Negotiate between multiple login contexts, this won't work.
* It is not preemptive.

I logged these issues in a jira: https://issues.apache.org/jira/browse/HTTPCLIENT-1912

So this example fixes the problem by performing the GSS login process ourselves. We will obtain the authorization token and add it to the HttpGet request as a header.

This example will show that we can use Negotiate authorization with a custom login context entry name and will download sample 984 files from the IIS server with multiple threads.

# How to setup this example using Windows IIS

We will do this example on Windows Server with IIS set up to do Kerberos auth.

## Set up IIS with Kerberos

You can follow this: 
https://blogs.msdn.microsoft.com/chiranth/2014/04/17/setting-up-kerberos-authentication-for-a-website-in-iis/

But specifically here's what you do: 

* On the Active Directory Server, create a new user to be the kerberos subject user
  * The new user in my case is:
    
    ```
    CN=kerberos,CN=Users,DC=yourdomain,DC=com
    kerberos@yourdomain.com
    WINLAB\kerberos
    ```

* Add a new application pool “WebKererosTest”
* Add a new web site to Sites:
  * Port: `81`
  * Folder: `c:\kerbtest`
* Go to Authentication for the site
  * Disable everything except Windows auth. 
  * Go to advanced settings of your application pool under which your website is running and change the identity to the domain account.
* Copy the test files for our test to download by doing the following:
  * Download http://downloads.digitalcorpora.org/corpora/files/govdocs1/zipfiles/100.zip
  * Do an "Extract Here" to `c:\kerbtest`.

At this point if you go to `http://yourhost:81/` you should get a 401 error without a valid Negotiate authorization header.

## Create the keytab on Windows

Example creates a keytab file `kerberos.keytab` for user principal `kerberos@YOURDOMAIN.COM`

`ktpass -out kerberos.keytab -princ kerberos@YOURDOMAIN.COM -mapUser kerberos -mapOp set -pass YOUR_PASSWORD -crypto ALL -pType KRB5_NT_PRINCIPAL`
Creating the KeyTab on Ubuntu Linux

Requires krb5-user package installed. I.e. `sudo apt-get install krb5-user`

Example creates a keytab file `kerberos.keytab` for user principal `kerberos@YOURDOMAIN.COM`

```
ktutil
addent -password -p kerberos@YOURDOMAIN.COM -k 1 -e RC4-HMAC
```

... It will ask you for password of kerberos...

```
wkt kerberos.keytab
q
```

## Create the login.conf

In this directory, create a `login.conf` and `krb5.ini` files as follows:

### login.conf for Windows

Example has the keystab stored at `c:\kerb\kerberos.keytab`

```
MyKrbLogin {
  com.sun.security.auth.module.Krb5LoginModule required
  useKeyTab=true
  storeKey=true
  keyTab="file:///C:/kerb/kerberos.keytab"
  useTicketCache=true
  principal="kerberos@YOURDOMAIN.COM"
  debug=true;
};
```
 
### login.conf for Linux

Example has keytab stored at `/home/myuser/kb.keytab`

```
MyKrbLogin {
  com.sun.security.auth.module.Krb5LoginModule required
  useKeyTab=true
  storeKey=true
  keyTab="/home/myuser/kb.keytab"
  useTicketCache=true
  principal="kerberos@YOURDOMAIN.COM"
  debug=true;
};
```

## Create a krb5.ini

Same steps for Linux and Windows here:
Example has domain YOURDOMAIN.COM, Kerberos kdc host is 192.168.1.71 and Kerberos admin server is 192.168.1.71.

```
[libdefaults]
    default_realm = YOURDOMAIN.COM
    default_tkt_enctypes = aes128-cts-hmac-sha1-96 rc4-hmac
    default_tgs_enctypes = aes128-cts-hmac-sha1-96  rc4-hmac
    permitted_enctypes = aes128-cts-hmac-sha1-96 rc4-hmac
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    udp_preference_limit = 1

[realms]
YOURDOMAIN.COM = {
   kdc = 192.168.1.71
   admin_server = 192.168.1.71
}

[domain_realm]
.YOURDOMAIN.COM = YOURDOMAIN.COM
YOURDOMAIN.COM = YOURDOMAIN.COM
```

The format is the login.conf is described here: https://docs.oracle.com/javase/8/docs/technotes/guides/security/jgss/tutorials/LoginConfigFile.html
The format of the krb5.ini file is described here: https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/krb5_conf.html

# Run the example

Now that you have everything setup.

* At the root of this project, `krb5.ini` and `login.conf`
* IIS site with sample files at `http://YOURHOST:81` where `YOURHOST` is the hostname of the web server protected by kerberos of which we are authenticating.

You can run the sample.

```
./gradlew clean build
java -cp build/libs/httpclient-tester-1.0.jar AsyncHttpSpnego YOURHOST
```
