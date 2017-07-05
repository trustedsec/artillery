:: Deletes cache files from folder in setup and uninstall
::
::clean cache from main dir
cd..
cd __pycache__
:: there is no pycache folder in py 2.7 .changed to pyc. to prevent from deleting all files in dir
echo y|del *.pyc
exit
exit
exit


