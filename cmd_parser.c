#include <cmd_parser.h>
#include <string.h>

#define ESCAPE_META '\\'

/* Separate a string using a delimiter that is not a space */
static unsigned int separate_string_char_delim(char *buf, char delim, char **array, unsigned int arraylen)
{
	enum tokenizer_state {
		START,
		FIND_DELIM
	} state = START;

	unsigned int count = 0;
	char *ptr = buf;
	int inside_quotes = 0;
	//unsigned int i;

	while (*ptr && count < arraylen) {
		switch (state) {
		case START:
			array[count++] = ptr;
			state = FIND_DELIM;
			break;

		case FIND_DELIM:
			/* escaped characters are copied verbatim to the destination string */
			if (*ptr == ESCAPE_META) {
				++ptr;
			} else if (*ptr == '\'' && (inside_quotes || strchr(ptr+1, '\''))) {
				inside_quotes = (1 - inside_quotes);
			} else if (*ptr == delim && !inside_quotes) {
				*ptr = '\0';
				state = START;
			}
			++ptr;
			break;
		}
	}
	/* strip quotes, escaped chars and leading / trailing spaces */

/*
	for (i = 0; i < count; ++i) {
		array[i] = cleanup_separated_string(array[i], delim);
	}
*/
	return count;
}

/* Separate a string using a delimiter that is a space */
static unsigned int separate_string_blank_delim(char *buf, char **array, unsigned int arraylen)
{
	enum tokenizer_state {
		START,
		SKIP_INITIAL_SPACE,
		FIND_DELIM,
		SKIP_ENDING_SPACE
	} state = START;

	unsigned int count = 0;
	char *ptr = buf;
	int inside_quotes = 0;
	//unsigned int i;

	while (*ptr && count < arraylen) {
		switch (state) {
		case START:
			array[count++] = ptr;
			state = SKIP_INITIAL_SPACE;
			break;

		case SKIP_INITIAL_SPACE:
			if (*ptr == ' ') {
				++ptr;
			} else {
				state = FIND_DELIM;
			}
			break;

		case FIND_DELIM:
			if (*ptr == ESCAPE_META) {
				++ptr;
			} else if (*ptr == '\'') {
				inside_quotes = (1 - inside_quotes);
			} else if (*ptr == ' ' && !inside_quotes) {
				*ptr = '\0';
				state = SKIP_ENDING_SPACE;
			}
			++ptr;
			break;

		case SKIP_ENDING_SPACE:
			if (*ptr == ' ') {
				++ptr;
			} else {
				state = START;
			}
			break;
		}
	}
	/* strip quotes, escaped chars and leading / trailing spaces */

/*
	for (i = 0; i < count; ++i) {
		array[i] = cleanup_separated_string(array[i], 0);
	}
*/
	return count;
}

unsigned int switch_separate_string_no_cleanup(char *buf, char delim, char **array, unsigned int arraylen)
{
	if (!buf || !array || !arraylen) {
		return 0;
	}


	if (*buf == '^' && *(buf+1) == '^') {
		char *p = buf + 2;

		if (*p && *(p+1)) {
			buf = p;
			delim = *buf++;
		}
	}


	memset(array, 0, arraylen * sizeof(*array));

	return (delim == ' ' ? separate_string_blank_delim(buf, array, arraylen) : separate_string_char_delim(buf, delim, array, arraylen));
}
