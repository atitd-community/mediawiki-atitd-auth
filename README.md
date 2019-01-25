This is a MediaWiki extension that performs authentication for users against the local Wiki if possible, or against the user's ATITD account if not.

First, the extension will try to log the user in by comparing the entered credentials to the local MediaWiki database. If it succeeds, the login proceeds normally. If it fails, the extension then attempts to verify the login credentials against the ATITD servers using an API endpoint provided by the game developers. If that succeeds, the extension creates a user in the local MediaWiki database and securely stores the user credentials for quicker authentication in the future.

Installation
============

  * Download and place the files in a directory called `ATITDAuth` in your `extensions/` folder.
  * Add the following code at the bottom of your LocalSettings.php:

```php
wfLoadExtension( 'ATITDAuth' );
$wgAuthManagerAutoConfig['primaryauth'][ATITDAuth\ATITDPasswordAuthenticationProvider::class] = [
	'class' => ATITDAuth\ATITDPasswordAuthenticationProvider::class,
	'args' => [ [
		'apiUrl' => 'https://www.ask-a-dev-for-this-endpoint-url.com',
		'timeout' => 20,
		'authoritative' => false
	] ],
	'sort' => 10,
];
```

  * Update the value of `apiUrl` as appropriate with the API endpoint used to authenticate ATITD game credentials.
  * Run `composer install` from within the `ATITDAuth` directory.
  * **Done** — Navigate to Special:Version on your wiki to verify that the extension is successfully installed.