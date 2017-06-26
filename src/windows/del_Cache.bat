:: Deletes cache files from folder in setup and uninstall
::
::clean cache from windows dir
cd __pycache__
echo y|del *.*
cd..
cd..
::clean cache from main dir
cd __pycache__
echo y|del *.*
exit
exit
exit


