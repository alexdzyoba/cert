package main

type TextFormatter struct {
	Verbosity  OutputLevel
	AppendRoot bool
}

func (f *TextFormatter) Format(report *Report) (string, error) {
	return "", nil
}
