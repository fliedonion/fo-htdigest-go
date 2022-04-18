package main

/*
 * fo-htdigest-go/src/cmd/fo-htdigest/main.go:
 *    simple program for manipulating digest passwd file for Apache
 * by fliedonion
 *
 * based on htdigest.c, by Alexei Kosut(, based on htpasswd.c, by Rob McCool)
 *
 * base program htdigest.c Licensed under Apache License 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

const (
	OptC           = "-c"
	tn             = "htdigest.tmp.*"
	MAX_STRING_LEN = 256
	MAX_LINE_LEN   = 768
)

var (
	logErr = log.New(os.Stderr, "", 0)
)

func usage(args []string) {
	fmt.Fprintf(os.Stderr, "Usage %s [-c] passwordfile realm username\n", args[0])
	fmt.Fprintf(os.Stderr, "The -c flag creates a new file.\n")
	os.Exit(1)
}

func readLine(r io.Reader) (string, error) {
	// なぜか改行が２つついてしまうのでやめた。

	in := bufio.NewReader(r)
	data, err := in.ReadString('\n')
	if err != nil {
		return "", err
	}

	// return data[:len(data)-1], nil  // Winだと \r が残る
	return strings.TrimRight(data, "\r\n"), nil
}

type ReadLineChanResult struct {
	ReadLine string
	Error    error
}

func readLineChannel(input chan ReadLineChanResult, r io.Reader) {
	in := bufio.NewReader(r)
	data, err := in.ReadString('\n')
	if err != nil {
		logErr.Println(err)
		input <- ReadLineChanResult{"", err}
	}

	input <- ReadLineChanResult{strings.TrimRight(data, "\r\n"), nil}
}

func readLineChannelByScanner(input chan ReadLineChanResult, r io.Reader) {
	// in := bufio.NewScanner(r)
	in := bufio.NewScanner(io.LimitReader(r, MAX_LINE_LEN))
	line := ""
	if in.Scan() {
		line = in.Text()
		// fmt.Println(line)
		input <- ReadLineChanResult{line, nil}
		return
	}
	if err := in.Err(); err != nil {
		logErr.Println(err)
		input <- ReadLineChanResult{"", err}
		return
	}
	// EOF
	input <- ReadLineChanResult{"", fmt.Errorf("detect EOF of reader while reading line")}
}

func addPassword(user string, realm string, f io.Writer) error {

	log.Println("TODO: Add Retype password feature")

	in := make(chan ReadLineChanResult, 1)
	defer close(in)
	go readLineChannelByScanner(in, os.Stdin)
	pwRead := <-in
	if pwRead.Error != nil {
		logErr.Println(pwRead.Error)
		return pwRead.Error
	}

	// "Re-type new password: "
	// "They don't match, sorry.\n"
	// cleanup_tempfile_and_exit(1);

	password := pwRead.ReadLine
	log.Println(password)
	log.Println(hex.EncodeToString([]byte(password)))

	fmt.Fprintln(f, makeHash(user, realm, password))

	return nil
}

func makeHash(user string, realm string, password string) string {

	if err := onlyPrintableAscii(user); err != nil {
		log.Fatal("user includes non ASCII character")
	}
	if err := onlyPrintableAscii(realm); err != nil {
		log.Fatal("realm includes non ASCII character")
	}
	if err := onlyPrintableAscii(password); err != nil {
		log.Fatal("password includes non ASCII character")
	}

	prefix := fmt.Sprintf("%s:%s:", user, realm)
	h := md5.New()
	h.Write([]byte(prefix + password))
	return prefix + hex.EncodeToString(h.Sum(nil))
}

func onlyPrintableAscii(text string) error {
	for _, c := range text {
		if c < 0x20 || 0x7E < c {
			log.Println(c)
			return fmt.Errorf("the string contains non ASCII or non Printable(0x20-0x7E) character")
		}
	}
	return nil
}

func main() {

	argc := len(os.Args)

	if argc == 5 {
		optc, pwFile := os.Args[1], os.Args[2]

		if optc != OptC {
			usage(os.Args)
		}

		// unlike original htdigest.exe , truncate file if already exist.
		f, err := os.Create(pwFile)
		// open file
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not open passwd file %s\n", pwFile)
			os.Exit(1)
		}
		defer f.Close()

		realm, user := os.Args[3], os.Args[4]

		fmt.Fprintf(os.Stderr, "Adding password for %s in realm %s.\n", user, realm)
		err = addPassword(user, realm, f)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	} else if argc != 4 {
		usage(os.Args)
	}

	dirname := os.TempDir()
	if dirname == "" {
		logErr.Println("could not determine temp dir")
		os.Exit(1)
	}

	tf, err := os.CreateTemp(dirname, tn)
	if err != nil {
		logErr.Printf("Could not open temp file %s/%s\n", dirname, tn)
		os.Exit(1)
	}

	tfn := tf.Name()

	defer func() {
		tf.Close()
		if err := os.Remove(tfn); err != nil {
			logErr.Println("error at removing temp file")
			logErr.Println(err)
		}
	}()

	pwFile := os.Args[1]
	realm, user := os.Args[2], os.Args[3]

	// 作成時以外はパーミッションは気にしなくていいらしい（既存ファイル操作では無視される）。
	f, err := os.OpenFile(pwFile, os.O_RDONLY, 0666)
	if err != nil {
		logErr.Printf("Could not open passwd file %s for reading.\n", pwFile)
		logErr.Println("Use -c option to create new one.")
		os.Exit(1)
	}
	defer f.Close()

	if err := updateTempPasswordFile(f, tf, user, realm); err != nil {
		logErr.Println(err)
		os.Exit(1)
	}

	f.Close()
	tf.Close()

	b, err := os.ReadFile(tfn)
	if err != nil {
		logErr.Printf("unable to update file %s -> %s\n", tfn, pwFile)
		logErr.Println(err)
		os.Exit(1)
	}
	if err := os.WriteFile(pwFile, b, 0644); err != nil {
		logErr.Printf("unable to update file %s -> %s\n", tfn, pwFile)
		logErr.Println(err)
		os.Exit(1)
	}
}

func updateTempPasswordFile(f io.Reader, tfp io.Writer, user string, realm string) error {
	in := bufio.NewScanner(f)
	putline := func(s string) {
		fmt.Fprintln(tfp, s)
	}

	found := false
	for in.Scan() {
		line := in.Text()
		if found || line == "" || line[0] == '#' {
			putline(line)
			continue
		}
		splited := strings.Split(line, ":")
		if len(splited) < 3 {
			putline(line)
			continue
		}
		u, r := splited[0], splited[1]
		if len(u) > (MAX_STRING_LEN-1) || len(r) > (MAX_STRING_LEN-1) {
			return fmt.Errorf("the line contains a string longer than the "+
				"allowed maximum size (%d)", MAX_STRING_LEN-1)
		}
		if u != user || r != realm {
			putline(line)
			continue
		} else {
			// change password
			fmt.Fprintf(os.Stderr, "Changing password for %s in realm %s.\n", user, realm)
			err := addPassword(user, realm, tfp)
			if err != nil {
				return err
			}
			found = true
			continue // To copy rest lines
		}
	}
	if err := in.Err(); err != nil {
		return err
	}

	if !found {
		// new user in realm
		fmt.Fprintf(os.Stderr, "Adding password for %s in realm %s.\n", user, realm)
		err := addPassword(user, realm, tfp)
		if err != nil {
			return err
		}
	}
	return nil
}
