if [ $# -lt 2 ];then
java -jar druid-plugin-1.1.5.beta-jar-with-dependencies.jar -help
else
java -Ddruid.debug=true -jar druid-plugin-1.1.5-jar-with-dependencies.jar $1 $2 $3 $4 $5
fi
