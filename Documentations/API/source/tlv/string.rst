String
======
Definition
^^^^^^^^^^
As shown in the figure :numref:`tlv_string` below, a **string** is encoded with:

 -  *Type* is the name of the string to set.
 -  *Length* is the number of bytes of *Value*.
 -  *Value* is the null terminated string value.


.. figure:: figures/tlv_string.png
   :align: center
   :name: tlv_string

   TLV string data

Example
^^^^^^^
The :numref:`tlv_string_example` is the coding of a string attribute
named *USER_NAME* set to "John Doe".

.. table:: Example of TLV string value
   :name: tlv_string_example
   :align: left
   :widths: 8 40 15 37
   :width: 100%
   :class: wrap-table

   +----------+---------------------+------------+-------------------------------+
   |          | **Type**            | **Length** | **Value**                     |
   +==========+=====================+============+===============================+
   | **Data** | USER_NAME           | 9          | John Doe                      |
   +----------+---------------------+------------+-------------------------------+
   | **Hex**  | 0x55 0x53 0x45 0x52 | 0x00 0x09  | 0x4A 0x6F 0x68 0x6E 0x20 0x44 |
   |          | 0x5F 0x4E 0x41 0x4D |            | 0x6F 0x65 0x00                |
   |          | 0x45 0x00           |            |                               |
   +----------+---------------------+------------+-------------------------------+
