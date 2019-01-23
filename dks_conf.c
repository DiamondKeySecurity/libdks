// Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
//
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "dks_conf.h"

// internal helper functions
char *LoadFile(const char *file_name_path);
char *GetXMLElementValue(char *xmldocument, const char *tag, const char *end_tag);

#define check_xml_result(op) if((op) == NULL) goto FREE_TEMPORARY_ALLOCATIONS

// load a conf file and create the necessary structures
hsm_conf_result_t LoadHSMInfo(hsm_info_t **hsm_info, hsm_port_type_t port_type)
{
    hsm_conf_result_t result = HSMCONF_OK;

    const char *conf_file_name = "/hsm.conf";
    const char *conf_path = getenv("DIAMOND_HSM_CONFIG_PATH");
    if(conf_path == NULL) conf_path = "/etc/dkey/hsm";

    *hsm_info = NULL;

    // variables that need to be freed at the end
    char *file_buffer = NULL;
    char *file_name_path = NULL;
    char *port = NULL;
    char *real_hsm_element = NULL;
    hsm_info_t *hsm_object = NULL;

    // create a string with the complete filename
    size_t buffer_len = strlen(conf_file_name) + strlen(conf_path) + 1;
    file_name_path = (char *)malloc(buffer_len);
    strcpy(file_name_path, conf_path);
    strcat(file_name_path, conf_file_name);

    file_buffer = LoadFile(file_name_path);
    if(file_buffer == NULL)
    {
        result = HSMCONF_FAILED_FILENOTFOUND;
        goto FREE_TEMPORARY_ALLOCATIONS;
    }

    char *xml_tag, *xml_tag_end;
    if(port_type == HSM_PORT_CTY)
    {
        xml_tag = "<cty>";
        xml_tag_end = "</cty>";
    }
    else if(port_type == HSM_PORT_RPC)
    {
        xml_tag = "<rpc>";
        xml_tag_end = "</rpc>";
    }
    else
    {
        result = HSMCONF_FAILED_PORTTYPENOTFOUND;
        goto FREE_TEMPORARY_ALLOCATIONS;
    }

    check_xml_result(real_hsm_element = GetXMLElementValue(file_buffer, xml_tag, xml_tag_end));

    // create the object
    hsm_object = malloc(sizeof(hsm_info_t));

    check_xml_result(hsm_object->servername = GetXMLElementValue(real_hsm_element, "<servername>", "</servername>"));
    check_xml_result(hsm_object->ip_addr = GetXMLElementValue(real_hsm_element, "<IP>", "</IP>"));
    check_xml_result(hsm_object->serial = GetXMLElementValue(real_hsm_element, "<serial>", "</serial>"));
    check_xml_result(port = GetXMLElementValue(real_hsm_element, "<port>", "</port>"));
    
    // check to make sure the port is valid
    hsm_object->port = strtol(port, NULL, 10);
    if(hsm_object->port == 0)
    {
        result = HSMCONF_FAILED_FORMAT;
        goto FREE_TEMPORARY_ALLOCATIONS;
    }

FREE_TEMPORARY_ALLOCATIONS:
    free(file_buffer);
    free(file_name_path);
    free(port);
    free(real_hsm_element);

    if(result != HSMCONF_OK)
        FreeHSMInfo(&hsm_object);
    else
    {
        // return the new data
        *hsm_info = hsm_object;
    }

    return result;
}

// free the data created using LoadHSMInfo
void FreeHSMInfo(hsm_info_t **hsm_info)
{
    // use a temporary point to save a dereference
    hsm_info_t *cur_obj;

    if(hsm_info != NULL)
    {
        cur_obj = *hsm_info;
        if(cur_obj != NULL)
        {
            if(cur_obj->ip_addr != NULL) free(cur_obj->ip_addr);
            if(cur_obj->servername != NULL) free(cur_obj->servername);
            if(cur_obj->serial != NULL) free(cur_obj->serial);

            free(cur_obj);
        }
    }

    // return NULL
    *hsm_info = NULL;
}

char *LoadFile(const char *file_name_path)
{
    // try to open the file
    FILE *fp = fopen(file_name_path, "rt");
    if(fp == NULL)
    {
        return NULL;
    }

    // load the entire file into a buffer
    fseek(fp, 0, SEEK_END);
    size_t file_buffer_size = ftell(fp)+1;
    if(file_buffer_size <= 1)
    {
        fclose(fp);
        return NULL;
    }

    fseek(fp, 0, SEEK_SET);
    char *file_buffer = (char *)malloc(file_buffer_size);
    memset(file_buffer, 0, file_buffer_size);

    char *file_pointer = file_buffer;
    int c = fgetc(fp);
    while(c != EOF)
    {
        *file_pointer = c;
        file_pointer++;
        c = fgetc(fp);
    }

    return file_buffer;    
}

char *GetXMLElementValue(char *xmldocument, const char *tag, const char *end_tag)
{
    char *xml_element = strstr(xmldocument, tag);
    int tag_size = strlen(tag);

    if(xml_element != NULL)
    {
        // get the size of the buffer that we will need
        char *xml_element_end = strstr(xml_element, end_tag);
        if (xml_element_end != NULL)
        {
            size_t count = (xml_element_end - xml_element) - tag_size;
            if(count > 0)
            {
                char *data_buffer = malloc(count + 1);
                memset(data_buffer, 0, count+1);
                if(data_buffer != NULL)
                {
                    strncpy(data_buffer, xml_element+tag_size, count);
                    return data_buffer;
                }
            }
        } 
    }
    return NULL;
}