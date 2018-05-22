rm cve-dictionary.log
rm cve.sqlite3

go-cve-dictionary fetchnvd -log-dir $(pwd) -years 2002 2003 2004 2005 2006 2007 2008 2009 2010 2011 2012 2013 2014 2015 2016 2017 2018

ls -halt
