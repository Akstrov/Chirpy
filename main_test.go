package main

import (
	"testing"
)

func TestCleaningChirp(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "test1",
			input: "kerfuffle",
			want:  "****",
		},
		{
			name:  "test2",
			input: "Kerfuffle",
			want:  "****",
		},
		{
			name:  "test3",
			input: "sharbert",
			want:  "****",
		},
		{

			name:  "test4",
			input: "Sharbert",
			want:  "****",
		},
		{
			name:  "test5",
			input: "fornax",
			want:  "****",
		},
		{
			name:  "test6",
			input: "Fornax",
			want:  "****",
		},
		{
			name:  "test7",
			input: "this is a test",
			want:  "this is a test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cleaningChirp(tt.input); got != tt.want {
				t.Errorf("cleaningChirp() = %v, want %v", got, tt.want)
			}
		})
	}
}
