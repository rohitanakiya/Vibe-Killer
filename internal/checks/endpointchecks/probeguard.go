package endpointchecks

import (
	"fmt"
	"regexp"
	"strings"
)

// This file is the last line of defence on what a probe may contain.
//
// The checks in this package are written to send benign values, and the
// reviews that matter happen when those checks are written. But a probe value
// is assembled from config, from a route template and from a nonce, and a
// mistake in any of those is a mistake that reaches someone's database. So
// every probe is also checked mechanically, immediately before it is sent, and
// a probe that could carry an effect is refused rather than sent.
//
// The guard is deliberately crude: it looks for the verbs and separators that
// turn a value into an instruction, and it does not try to parse. A false
// refusal costs a check its finding, which is the right way round.

// destructiveVerb matches the statement keywords that change or destroy data.
// A detection probe never needs any of them: a weakness is established by what
// comes back, not by what is altered.
var destructiveVerb = regexp.MustCompile(
	`(?i)\b(drop|delete|truncate|alter|create|insert|update|replace|merge|grant|revoke|shutdown|` +
		`rename|exec|execute|xp_cmdshell|sp_executesql|load_file|outfile|dumpfile|` +
		`into\s+outfile|benchmark|sleep|waitfor|pg_sleep|dbms_pipe)\b`)

// statementSeparator matches the characters that let a value end one statement
// and begin another, or append a shell command.
var statementSeparator = regexp.MustCompile(`[;&|` + "`" + `]|\$\(|--\s|/\*|\*/`)

// ErrUnsafeProbe is returned when a probe value is refused.
type ErrUnsafeProbe struct {
	RuleID string
	Value  string
	Reason string
}

func (e *ErrUnsafeProbe) Error() string {
	return fmt.Sprintf("refusing to send a probe for %s: %s (value: %q). "+
		"Detection probes must be inert; this one could have an effect",
		e.RuleID, e.Reason, e.Value)
}

// assertInertProbe refuses any probe value that could carry an effect.
//
// It is called by every check that puts a crafted value into a request, and it
// returns an error rather than sanitizing, because a probe that needed
// sanitizing was built wrongly and the check should be fixed.
func assertInertProbe(ruleID, value string) error {
	if destructiveVerb.MatchString(value) {
		return &ErrUnsafeProbe{
			RuleID: ruleID, Value: value,
			Reason: "it contains a statement keyword that changes or destroys data",
		}
	}
	if statementSeparator.MatchString(value) {
		return &ErrUnsafeProbe{
			RuleID: ruleID, Value: value,
			Reason: "it contains a separator that could end one statement and begin another",
		}
	}
	// A probe long enough to hide something is a probe nobody reviewed.
	if len(value) > 120 {
		return &ErrUnsafeProbe{
			RuleID: ruleID, Value: value,
			Reason: "it is longer than any detection probe needs to be",
		}
	}
	return nil
}

// assertInertProbes checks several values at once.
func assertInertProbes(ruleID string, values ...string) error {
	for _, v := range values {
		if err := assertInertProbe(ruleID, v); err != nil {
			return err
		}
	}
	return nil
}

// sqlErrorSignatures are strings that only a database driver produces.
//
// They are what distinguishes an injection finding from the generic
// verbose-error finding: a traceback says the handler crashed, while one of
// these says the value reached a SQL parser as syntax.
// The order matters, and the list is deliberately most-specific-first.
// Several engines produce overlapping phrases: PostgreSQL's "syntax error at
// or near \"'\"" also contains SQLite's "near \"", so a list that checked the
// short generic fragment first would name the wrong engine in the evidence.
// The module-qualified names go first, then the engine-specific phrases, and
// the short fragments last.
var sqlErrorSignatures = []struct {
	needle, engine string
}{
	// Module-qualified: unambiguous.
	{"psycopg2.errors", "PostgreSQL"},
	{"psycopg.errors", "PostgreSQL"},
	{"asyncpg.exceptions", "PostgreSQL"},
	{"sqlite3.OperationalError", "SQLite"},
	{"sqlite3.Warning", "SQLite"},
	{"SQLiteException", "SQLite"},
	{"SequelizeDatabaseError", "Sequelize"},
	{"QueryFailedError", "TypeORM"},
	{"PrismaClientKnownRequestError", "Prisma"},
	{"MySQLdb._exceptions", "MySQL"},
	{"pymysql.err", "MySQL"},

	// Engine-specific codes and phrases.
	{"ER_PARSE_ERROR", "MySQL"},
	{"You have an error in your SQL syntax", "MySQL"},
	{"SQLSTATE[", "a PDO driver"},
	{"syntax error at or near", "PostgreSQL"},
	{"unterminated quoted string", "PostgreSQL"},
	{"ORA-00933", "Oracle"},
	{"ORA-01756", "Oracle"},
	{"Unclosed quotation mark", "SQL Server"},
	{"Incorrect syntax near", "SQL Server"},

	// Short fragments, checked only once nothing more specific matched.
	{"unrecognized token", "SQLite"},
	{"near \"", "SQLite"},
	{"ProgrammingError", "a Python DB-API driver"},
	{"OperationalError", "a Python DB-API driver"},
}

// matchSQLError reports which database engine's parser produced an error, if
// the response carries one.
func matchSQLError(body string) (engine string, found bool) {
	for _, sig := range sqlErrorSignatures {
		if strings.Contains(body, sig.needle) {
			return sig.engine, true
		}
	}
	return "", false
}

// nosqlOperatorSignatures indicate a document-store query layer complaining
// about an operand it was given.
var nosqlOperatorSignatures = []string{
	"MongoServerError",
	"unknown operator",
	"BSONTypeError",
	"CastError",
	"$gt",
	"$ne",
}

// matchNoSQLError reports whether a response shows a document-store query
// layer interpreting the value as an operator.
func matchNoSQLError(body string) bool {
	for _, s := range nosqlOperatorSignatures {
		if strings.Contains(body, s) {
			return true
		}
	}
	return false
}
