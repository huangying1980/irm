IRM_1.0.0 {
    global:
        irm_pub_socket;
        irm_pub_bind;
        irm_pub_close;
        irm_pub_alloc;
        irm_pub_send;
        irm_pub_free;
        irm_pub_getalivedsubs;

        irm_sub_socket;
        irm_sub_bind;
        irm_sub_close;
        irm_sub_recv;
        irm_sub_free;
        irm_sub_getalivedpubs;

        irm_pub_setsockopt;
        irm_pub_getsockopt;

        irm_sub_setsockopt;
        irm_sub_getsockopt;

        irm_errno;
   
    local:*;
};
