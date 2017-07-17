#include <stdio.h>

int main(void) {
	FILE *f = fopen("loader.bin", "rb");
	fseek(f, 0, SEEK_END);
	int s = ftell(f);
	rewind(f);

	FILE *o = fopen("loader.js", "wb");

	int i;
	for(i = 0; i < s / 4; i++) {
		unsigned int u;
		fread(&u, sizeof(u), 1, f);
		fprintf(o, "cbuf[%d] = 0x%08x;\n", i, u);

		//if(u == 0) break;
	}

	fclose(o);
	fclose(f);

	return 0;
}
