
// Given a certificate (cert) verify that it's
// common name matches our target domain 
// (our_domain).

// Return codes:
// -1 -> Error
//  1 -> Cert CN matches our_domain
//  0 -> Cert CN does not match our_domain

int verify_cert_cn(X509* cert, char* our_domain)
{

    if (cert == NULL || our_domain == NULL)
        return -1;
    
    char *byte_arr;
    int arr_size;
    
    // - extract_sn takes a cert and returns that certificate's subject name as
    //   an array of bytes.  
    // - The subject name is the CN, country, city, etc etc.  
    // - The format of the returned subject name is each field is delimited with a /
    //   Example (the order of the arguments is not deterministic)
    //   /CN=example.com/ST=California/C=US/emailAddress=admin@example.com/O=Examples,Inc/OU=None
    arr_size = extract_sn(cert, &byte_arr);

    if (arr_size <= 0)
        return -1;

    // Find the CN
    int cn_start_idx = -1;
    int cn_end_idx = arr_size - 1;
    for (int i = 0; i < arr_size; i++)
    { 
        if (byte_arr[i] == '/' && (i + 3) < arr_size
                               && byte_arr[i+1] == 'C'
                               && byte_arr[i+2] == 'N'
                               && byte_arr[i+3] == '='
           )
        {
            cn_start_idx = i + 4;
            break;
        }
    }

    if (cn_start_idx < 0 || cn_start_idx >= arr_size)
        return -1;
    
    // At this point cn_start_idx has the point in byte_arr of the start of our CN
    // In our example, that would be the position of the 'e' in example.com

    // Now find where the CN ends. Look for the next delimiter
    for (int i = cn_start_idx; i < arr_size; i++)
    {
        if (byte_arr[i] == '/')
        {
            cn_end_idx = i - 1;
            break;
        }
    }
    
    if (cn_start_idx == cn_end_idx)
        return -1;

    // Now cn_end_idx has the last character of the CN

    int cn_len = cn_end_idx - cn_start_idx + 1;
    char *cn = malloc(cn_len + 1); // +1 for the null terminator
    
    if (cn == NULL)
        return -1;

    // Copy the CN, null terminate it.
    memcpy(cn, byte_arr + cn_start_idx, cn_len);
    cn[cn_len] = '\0';

    // Now compare the CN against our_domain
    int result = strcmp(cn, our_domain);
    
    free(cn);
    
    if (result == 0)
        return 1;
    else
        return 0;
}


