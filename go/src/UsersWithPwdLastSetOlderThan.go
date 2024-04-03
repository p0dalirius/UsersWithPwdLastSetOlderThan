package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/xuri/excelize/v2"
)

func banner() {
	fmt.Printf("UsersWithPwdLastSetOlderThan v%s - by @podalirius_\n", "1.3")
	fmt.Println("")
}

func ldap_init_connection(host string, port int, username string, domain string, password string) (*ldap.Conn, error) {
	// Check if TCP port is valid
	if port < 1 || port > 65535 {
		fmt.Println("[!] Invalid port number. Port must be in the range 1-65535.")
		return nil, errors.New("invalid port number")
	}

	// Set up LDAP connection
	ldapSession, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		fmt.Println("[!] Error connecting to LDAP server:", err)
		return nil, nil
	}

	// Bind with credentials if provided
	bindDN := ""
	if username != "" {
		bindDN = fmt.Sprintf("%s@%s", username, domain)
	}
	if bindDN != "" && password != "" {
		err = ldapSession.Bind(bindDN, password)
		if err != nil {
			fmt.Println("[!] Error binding:", err)
			return nil, nil
		}
	}

	return ldapSession, nil
}

func ldap_get_rootdse(ldapSession *ldap.Conn) *ldap.Entry {
	// Specify LDAP search parameters
	// https://pkg.go.dev/gopkg.in/ldap.v3#NewSearchRequest
	searchRequest := ldap.NewSearchRequest(
		// Base DN blank
		"",
		// Scope Base
		ldap.ScopeBaseObject,
		// DerefAliases
		ldap.NeverDerefAliases,
		// SizeLimit
		1,
		// TimeLimit
		0,
		// TypesOnly
		false,
		// Search filter
		"(objectClass=*)",
		// Attributes to retrieve
		[]string{"*"},
		// Controls
		nil,
	)

	// Perform LDAP search
	searchResult, err := ldapSession.Search(searchRequest)
	if err != nil {
		fmt.Println("[!] Error searching LDAP:", err)
		return nil
	}

	return searchResult.Entries[0]
}

var (
	useLdaps     bool
	quiet        bool
	debug        bool
	ldapHost     string
	ldapPort     int
	authDomain   string
	authUsername string
	// noPass         bool
	authPassword string
	authHashes   string
	// authKey        string
	// useKerberos    bool
	xlsx         string
	days         int
)

func parseArgs() {
	flag.BoolVar(&useLdaps, "use-ldaps", false, "Use LDAPS instead of LDAP.")
	flag.BoolVar(&quiet, "quiet", false, "Show no information at all.")
	flag.BoolVar(&debug, "debug", false, "Debug mode")

	flag.IntVar(&days, "days", 365, "Number of days since last password change.")

	flag.StringVar(&ldapHost, "host", "", "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter.")
	flag.IntVar(&ldapPort, "port", 0, "Port number to connect to LDAP server.")

	flag.StringVar(&authDomain, "domain", "", "(FQDN) domain to authenticate to.")
	flag.StringVar(&authUsername, "username", "", "User to authenticate as.")
	//flag.BoolVar(&noPass, "no-pass", false, "don't ask for password (useful for -k)")
	flag.StringVar(&authPassword, "password", "", "password to authenticate with.")
	flag.StringVar(&authHashes, "hashes", "", "NT/LM hashes, format is LMhash:NThash.")
	//flag.StringVar(&authKey, "aes-key", "", "AES key to use for Kerberos Authentication (128 or 256 bits)")
	//flag.BoolVar(&useKerberos, "k", false, "Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")

	flag.StringVar(&xlsx, "xlsx", "", "Output results in a XLSX Excel file.")

	flag.Parse()

	if ldapHost == "" {
		fmt.Println("[!] Option -host <host> is required.")
		flag.Usage()
		os.Exit(1)
	}

	if ldapPort == 0 {
		if useLdaps {
			ldapPort = 636
		} else {
			ldapPort = 389
		}
	}
}

func main() {
	banner()
	parseArgs()

	if xlsx == "" {
		xlsx = fmt.Sprintf("UsersWithPwdLastSetOlderThan_%d_days_%s.xlsx", days, strings.ToLower(authDomain))
	}

	if debug {
		if !useLdaps {
			fmt.Printf("[debug] Connecting to remote ldap://%s:%d ...\n", ldapHost, ldapPort)
		} else {
			fmt.Printf("[debug] Connecting to remote ldaps://%s:%d ...\n", ldapHost, ldapPort)
		}
	}

	// Init the LDAP connection
	ldapSession, err := ldap_init_connection(ldapHost, ldapPort, authUsername, authDomain, authPassword)
	if err != nil {
		fmt.Println("[!] Error searching LDAP:", err)
		return
	}

	rootDSE := ldap_get_rootdse(ldapSession)
	if debug {
		fmt.Printf("[debug] Using defaultNamingContext %s ...\n", rootDSE.GetAttributeValue("defaultNamingContext"))
	}

	// Specify LDAP search parameters
	// https://pkg.go.dev/gopkg.in/ldap.v3#NewSearchRequest
	searchRequest := ldap.NewSearchRequest(
		// Base DN
		rootDSE.GetAttributeValue("defaultNamingContext"),
		// Scope
		ldap.ScopeWholeSubtree,
		// DerefAliases
		ldap.NeverDerefAliases,
		// SizeLimit
		0,
		// TimeLimit
		0,
		// TypesOnly
		false,
		// Search filter
		"(objectClass=person)",
		// Attributes to retrieve
		[]string{
			"name",
			"sAMAccountName",
			"distinguishedName",
			"description",
			"memberOf",
			"pwdLastSet",
			"whenCreated",
			"lastLogon",
			"logonCount", 
			"lastLogonTimestamp",
			"lastLogoff",
			"adminCount",
			"accountExpires",
		},
		// Controls
		nil,
	)

	// Perform LDAP search
	fmt.Println("[+] Extracting all users ... ")
	searchResult, err := ldapSession.SearchWithPaging(searchRequest, 1000)
	if err != nil {
		fmt.Println("[!] Error searching LDAP:", err)
		return
	}
	
	// Print search results
	var resultsList []map[string]string
	for _, entry := range searchResult.Entries {
	
		pwdLastSet := entry.GetAttributeValue("pwdLastSet")
		pwdLastSetInt, err := strconv.ParseInt(pwdLastSet, 10, 64)
		if err != nil {
			fmt.Println("[!] Error converting pwdLastSet to float64:", err)
			continue
		}
		const unixTimestampStart int64 = 116444736000000000 // Monday, January 1, 1601 12:00:00 AM
		pwdLastSetTime := time.Unix(0, int64((pwdLastSetInt-unixTimestampStart)*100))
		daysSincePwdLastSet := time.Since(pwdLastSetTime).Hours() / 24

		if daysSincePwdLastSet >= float64(days) {
			result := make(map[string]string)

			result["name"] = entry.GetAttributeValue("name")
			result["sAMAccountName"] = entry.GetAttributeValue("sAMAccountName")
			result["distinguishedName"] = entry.GetAttributeValue("distinguishedName")
			result["description"] = entry.GetAttributeValue("description")
			result["memberOf"] = entry.GetAttributeValue("memberOf")
			result["pwdLastSet"] = entry.GetAttributeValue("pwdLastSet")
			result["whenCreated"] = entry.GetAttributeValue("whenCreated")
			result["lastLogon"] = entry.GetAttributeValue("lastLogon")
			result["logonCount"] = entry.GetAttributeValue("logonCount")
			result["lastLogonTimestamp"] = entry.GetAttributeValue("lastLogonTimestamp")
			result["lastLogoff"] = entry.GetAttributeValue("lastLogoff")
			result["adminCount"] = entry.GetAttributeValue("adminCount")
			result["accountExpires"] = entry.GetAttributeValue("accountExpires")

			resultsList = append(resultsList, result)
		}
	}

	// Export BitLocker Recovery Keys to an Excel
	if xlsx != "" {
		f := excelize.NewFile()
		// Create a new sheet.
		index, err := f.NewSheet("Sheet1")
		if err != nil {
			fmt.Println("[!] Error creating sheet:", err)
			return
		}
		// Set value of a cell.
		f.SetCellValue("Sheet1", "A1", "name")
		f.SetCellValue("Sheet1", "B1", "sAMAccountName")
		f.SetCellValue("Sheet1", "C1", "distinguishedName")
		f.SetCellValue("Sheet1", "D1", "description")
		f.SetCellValue("Sheet1", "E1", "memberOf")
		f.SetCellValue("Sheet1", "F1", "pwdLastSet")
		f.SetCellValue("Sheet1", "G1", "whenCreated")
		f.SetCellValue("Sheet1", "H1", "lastLogon")
		f.SetCellValue("Sheet1", "I1", "logonCount")
		f.SetCellValue("Sheet1", "J1", "lastLogonTimestamp")
		f.SetCellValue("Sheet1", "K1", "lastLogoff")
		f.SetCellValue("Sheet1", "L1", "adminCount")
		f.SetCellValue("Sheet1", "M1", "accountExpires")

		for i, result := range resultsList {
			f.SetCellValue("Sheet1", fmt.Sprintf("A%d", i+2), result["name"])
			f.SetCellValue("Sheet1", fmt.Sprintf("B%d", i+2), result["sAMAccountName"])
			f.SetCellValue("Sheet1", fmt.Sprintf("C%d", i+2), result["distinguishedName"])
			f.SetCellValue("Sheet1", fmt.Sprintf("D%d", i+2), result["description"])
			f.SetCellValue("Sheet1", fmt.Sprintf("E%d", i+2), result["memberOf"])
			f.SetCellValue("Sheet1", fmt.Sprintf("F%d", i+2), result["pwdLastSet"])
			f.SetCellValue("Sheet1", fmt.Sprintf("G%d", i+2), result["whenCreated"])
			f.SetCellValue("Sheet1", fmt.Sprintf("H%d", i+2), result["lastLogon"])
			f.SetCellValue("Sheet1", fmt.Sprintf("I%d", i+2), result["logonCount"])
			f.SetCellValue("Sheet1", fmt.Sprintf("J%d", i+2), result["lastLogonTimestamp"])
			f.SetCellValue("Sheet1", fmt.Sprintf("K%d", i+2), result["lastLogoff"])
			f.SetCellValue("Sheet1", fmt.Sprintf("L%d", i+2), result["adminCount"])
			f.SetCellValue("Sheet1", fmt.Sprintf("M%d", i+2), result["accountExpires"])
		}
		// Set active sheet of the workbook.
		f.SetActiveSheet(index)
		// Save xlsx file by the given path.
		if err := f.SaveAs(xlsx); err != nil {
			fmt.Println(err)
		}
		fmt.Printf("[+] Written %d users with pwdLastSet older than %d days to %s\n", len(resultsList), days, xlsx)
		
	} else {
		// Print the keys in the console
		for _, result := range resultsList {
			fmt.Printf("   [>] (pwdLastSet=%s) for %s ...\n", result["pwdLastSet"], result["distinguishedName"])
		}
	}

	fmt.Println("[+] All done!")
}
