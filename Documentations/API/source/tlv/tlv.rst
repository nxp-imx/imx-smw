TLV coding
==========

The TLV is a Type-Length-Value coding scheme. Encoding data with this format
allows to define optional information with variable length in a non-sorted
list of data.

In the context of the Security Middleware library, the TLV data format is
used to pass optional operation parameter(s) without dedicated operation
argument structure field(s).

The **Type** is encoded as an ASCII string terminated with the null character.
The possible values are specific to each operation.

The **Length** field is length in bytes of the **Value** field encoded with
two bytes (MSB first).
A length of 0 implies that **Value** field is not present.

The **Value** field is a byte stream that contains the data.
Different type of data are supported: null terminated string, numeral, variable
length list (TLV encoded list).

The :numref:`tlv_encoding` shows the binary translation of any type of TLVs.

.. figure:: figures/tlv_encoding.png
   :align: center
   :name: tlv_encoding

   Binary view of TLV encoded data

The TLV types are described in the following sections.

.. toctree::
   :maxdepth: 1
   :glob:

   boolean
   numeral
   string
   variable-length