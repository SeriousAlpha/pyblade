from main import Analyzer

def scan(files):
    for name, lines in files.iteritems():
        judge = Analyzer(name,  lines)
        judge.parse_py()
        judge.source_to_sink()
        judge.record_all_func()
