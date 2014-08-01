.phony : id query build clean

build:
	@echo "Nothing to build... just run 'make id' or 'make query' and then clean up the temp files with 'make clean'"

poll_new.tmp:
	@awk -F, '{print $$3}' Poll-Data.csv | awk -F- '{print $$3}' | paste -d , Poll-Data.csv - > poll_new.tmp

id: poll_new.tmp
	@cat q5_id.sql | sqlite3

query: poll_new.tmp
	@cat q5_query.sql | sqlite3 | awk '{printf("%.2f\n", $$1)}'

clean:
	rm -f poll_new.tmp
