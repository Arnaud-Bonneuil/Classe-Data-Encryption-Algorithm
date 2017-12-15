#include <stdio.h> /* printf, getchar */
#include <stdlib.h> /* EXIT_SUCCESS */

#include "Classe_Data_Encryption_Standard.h"


int main ( int argc, char *argv[] )
{
    type_clef_des clef = {0};
    uint8_t message[8] = {0};
    uint8_t message_code[8] = {0};
    uint8_t message_decode[8] = {0};
    int i;

    (clef.clef_initiale)[0] = 0x13;
    (clef.clef_initiale)[1] = 0x34;
    (clef.clef_initiale)[2] = 0x57;
    (clef.clef_initiale)[3] = 0x79;
    (clef.clef_initiale)[4] = 0x9B;
    (clef.clef_initiale)[5] = 0xBC;
    (clef.clef_initiale)[6] = 0xDF;
    (clef.clef_initiale)[7] = 0xF1;

    DEA_Generer_Sous_Clefs( &clef );
    printf( "Clef :\n" );
    DEA_Afficher_Clef( &clef );
    printf( "\n" );

    message[0] = 0x01;
    message[1] = 0x23;
    message[2] = 0x45;
    message[3] = 0x67;
    message[4] = 0x89;
    message[5] = 0xAB;
    message[6] = 0xCD;
    message[7] = 0xEF;

    DEA_Appliquer_Aglorithme( &clef, message, message_code, CHIFFREMENT );

    printf( "message clair :   " );
    for( i=0 ; i<8 ; i++ )
    {
    	printf( "%02X", message[i] );
    }
	printf( "\n" );

	printf( "message chiffre : " );
    for( i=0 ; i<8 ; i++ )
    {
    	printf( "%02X", message_code[i] );
    }
	printf( "\n" );

	DEA_Appliquer_Aglorithme( &clef, message_code, message_decode, DECHIFFREMENT );

	printf( "message clair :   " );
    for( i=0 ; i<8 ; i++ )
    {
    	printf( "%02X", message_decode[i] );
    }
	printf( "\n" );

    getchar();
    return EXIT_SUCCESS;
}
