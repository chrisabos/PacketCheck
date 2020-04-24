
# these values are found from RFC 4595
# https://tools.ietf.org/html/rfc4594#section-1.4.4

dscp_dict = {
    0b110000: "CS6 - Network Routing",
    0b101000: "CS5 - IP Telephony signaling",
    0b100000: "CS4 - Video Conferencing and Interactive gaming",
    0b011000: "CS3 - Broadcast TV & live events",
    0b010000: "CS2 - OAM&P",
    0b001000: "CS1 - No BW assurance",
    0b000000: "DF - Undifferentiated application",
    0b001010: "AF11 - Store and forward",
    0b001100: "AF12 - Store and forward",
    0b001110: "AF13 - Store and forward",
    0b010010: "AF21 - Client/Server transaction",
    0b010100: "AF22 - Client/Server transaction",
    0b010110: "AF23 - Client/Server transaction",
    0b011010: "AF31 - Streaming audio/video",
    0b011100: "AF32 - Streaming audio/video",
    0b011110: "AF33 - Streaming audio/video",
    0b100010: "AF41 - H.323/V2 video conferencing",
    0b100100: "AF42 - H.323/V2 video conferencing",
    0b100110: "AF43 - H.323/V2 video conferencing",
    0b101110: "EF - IP Telephony bearer"
}

def lookup(n):
    ret = dscp_dict.get(n)
    if ret == None:
        return "Unknown"
    return ret
