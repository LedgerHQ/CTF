unsigned char zecrc[16] = {0x9b,0x04,0x57,0x44,0xe5,0x1f,0xf0,0xf9,0xe8,0x4a,0x54,0xda,0x68,0xe0,0x52,0xb8};

void genSboxes(word8 keys[11][4][4], word8 masks[4][4]){
    shiftrows(keys[10]);
    shiftrows(keys[10]);
    shiftrows(keys[10]);
    for(int r = 0; r < 11; r++)
       for(int j = 0; j < 4; j++)
          for(int k = 0; k < 4; k++)
             for(int l = 0; l < 256; l++)
                for(int m = 0; m < 256; m++){
                    if(r == 9) sboxes[r][j][k][l][m] = S[m ^ l ^ keys[r][j][k]] ^ zecrc[j*4+k] ^ m ^ keys[10][j][k];
                    else sboxes[r][j][k][l][m] = S[m ^ l ^ keys[r][j][k]] ^ zecrc[j*4+k] ^ m;
                }
}

void printBoxes(){
    printf("unsigned char sboxes[11][4][4][256][256]={");
    for(int r = 0; r < 11; r++){
       printf("{");
       for(int j = 0; j < 4; j++){
	  printf("{");
          for(int k = 0; k < 4; k++){
	     printf("{");
             for(int l = 0; l < 256; l++){
                printf("{");
                for(int m = 0; m < 255; m++){
                   printf("0x%02x,",sboxes[r][j][k][l][m]);
                }
                printf("0x%02x},\n",sboxes[r][j][k][l][255]);
             }
           printf("},");
          }
          printf("},");
       }
       printf("},");
    }
    printf("};");
}

