# Custom user authentication with webapp2

This is a skeleton implementation of user account management with webapp2.

You will have to take care of the following items:

* ~~Implement user registration~~
* ~~Write code to handle login~~
* ~~Setup email verification and password recovery~~ (This has been done for you already)
* Send email verification and password recovery messages via email
* [Configure](https://developers.google.com/appengine/docs/python/config/appconfig#Secure_URLs) login and password reset urls to use https (you will have to deploy your app to test this)

You can find most of the logic in `main.py` (even though you may want to put handlers in separate files, as your app grows in complexity), a custom user model in `models.py`, and some extremely simple views in `views`.

## More information

You can find a detailed tutorial in this blog post: [Custom user authentication with webapp2](http://blog.abahgat.com/2013/01/07/user-authentication-with-webapp2-on-google-app-engine).
