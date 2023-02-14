package benchmark_tests

import (
	"flag"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
)

// structToMap decodes the config structs defined in tests to maps so
// they can be passed in as part of the Vault API request
func structToMap(in interface{}) (map[string]interface{}, error) {
	tMap := make(map[string]interface{})
	tDecoderConfig := mapstructure.DecoderConfig{
		Result:  &tMap,
		TagName: "hcl",
	}
	tDecoder, err := mapstructure.NewDecoder(&tDecoderConfig)
	if err != nil {
		return nil, fmt.Errorf("error configuring decoder: %v", err)
	}

	err = tDecoder.Decode(in)
	if err != nil {
		return nil, fmt.Errorf("error decoding role config from struct: %v", err)
	}
	return tMap, nil
}

// ConfigOverrides accepts a config interface and will walk through all passed in flags
// and set the relevant config parameters that match based on hcl tag. This expects the
// tag name and the flag name to match. This feels fragile, as if anything goes wrong
// this will cause a panic. By this point everything should have gone through HCL parsing
// and the flag package so it shouldn't be too bad.
func ConfigOverrides(conf interface{}) error {
	var err error
	flag.Visit(func(f *flag.Flag) {
		// Walk all the keys of the config struct
		r := reflect.ValueOf(conf).Elem()

		for i := 0; i < r.NumField(); i++ {
			// Get Field name match by tag
			tag := r.Type().Field(i).Tag.Get("hcl")
			if tag == "" || tag == "-" {
				continue
			}
			args := strings.Split(tag, ",")

			// Match the flag against the tag
			if args[0] == f.Name {
				if r.Field(i).CanSet() {
					switch r.Field(i).Kind() {
					case reflect.Bool:
						r.Field(i).SetBool(f.Value.(flag.Getter).Get().(bool))
					case reflect.String:
						// Check if we need to grab the string value of a time.Duration flag
						if t, ok := f.Value.(flag.Getter).Get().(time.Duration); ok {
							r.Field(i).SetString(t.String())
							continue
						}
						r.Field(i).SetString(f.Value.(flag.Getter).Get().(string))
					case reflect.Int:
						r.Field(i).SetInt(f.Value.(flag.Getter).Get().(int64))
					}
				} else {
					// Unable to set
					err = fmt.Errorf("unable to set field: %v", f.Name)
				}
			}
			// Log that we didn't find a match for the flag
			// We honestly probably won't get here.... If we do then the issue
			// is that the flag and the tags don't match and is a code problem
			// We should probably issue a warning via CLI but we need to move
			// to using CLI first.
			fmt.Printf("unable to find match for flag %v\n", f.Name)
		}

	})
	return err
}
