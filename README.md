# proxme
Localhost proxy to allow local resources being accesible with proper CORS Policy in place

Start on command line by using:
python proxme.py <PORT> <TARGET> <ALLOWED_ORIGIN?>

e.g.
python proxme.py 9999 http://localhost:8080 https://sunshyne.me

if you leave ALLOWED_ORIGIN out, it will allow all incoming requests!