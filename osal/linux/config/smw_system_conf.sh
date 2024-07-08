#!/bin/sh
set -eu

script_name=$0

find_in_file()
{
  index=0
  start_at="$2"
  filename="$3"
  pattern="$4"
  next_section=0
  found=0

  while read -r line
  do
    index=$((index+1))

    if [ "${index}" -gt "${start_at}" ]; then
      case $line in
        \[*)
          line=$(echo "${line}" | sed -e "s/.*/\L&/")

          if [ "${line}" = "${pattern}" ]; then
            found=1
            break
          fi
          if [ "${start_at}" -ne 0 ]; then
            next_section=1
            index=$((index-1))
            break
          fi
          ;;

        ${pattern})
          found=1
          break
          ;;
      esac
    fi
  done < "${filename}"

  eval "$5=${found}"

  if [ "${found}" -eq 1 ] || [ "${next_section}" -eq 1 ]; then
    eval "$1=${index}"
  else
    eval "$1=0"
  fi
}

find_replace_entry()
{
  section_at="$1"
  filename="$2"
  entry="$3"
  value="$4"
  line_nb=0
  match=0

  # Find if the entry is already present in the file
  while [ "${line_nb}" -lt "${section_at}" ]
  do
    find_in_file line_nb "${section_at}" "${filename}" "${entry}=*" match

    if [ "${line_nb}" -eq 0 ]; then
      break;
    fi
  done

  if [ "${line_nb}" -eq 0 ] || [ "${match}" -eq 0 ]; then
    # Find in the section if there is a comment for the entry and
    # add the entry value after.
    find_in_file line_nb "${section_at}" "${filename}" "*${entry}*" match
    if [ "${line_nb}" -eq 0 ] || [ "${match}" -eq 0 ]; then
      line_nb="${section_at}"
    fi

    line_nb=$((line_nb+1))
    sed -i "${line_nb}i ${entry}=${value}" "${filename}"
  else
    value=$(echo "${value}" | sed -e "s/\//\\\\\//g")
    sed -i -e "${line_nb} s/.*/${entry}=${value}/" "${filename}"
  fi
}

set_conf_entry()
{
  filename="$1"
  section="$2"
  entry="$3"
  value="$4"
  line_nb=0
  match=0

  find_in_file line_nb 0 "${filename}" "[${section}]" match

  if [ "${line_nb}" -eq 0 ]; then
    # Section not present in the file
    printf "\n%s\n" "[${section}]" >> "${filename}"
    printf "%s=%s\n" "${entry}" "${value}" >> "${filename}"
  else
    find_replace_entry "${line_nb}" "${filename}" "${entry}" "${value}"
  fi
}

usage()
{
  printf "\n"
  printf "************************************************************\n"
  printf "* Usage of Security Middleware system configuration script *\n"
  printf "************************************************************\n"
  printf "\n"

  printf "Script read the SMW system configuration file specify as input "
  printf "and enabling the configuration option requested.\n"
  printf "Resulting configuration file if given as output is created, else "
  printf "input file is overwritten.\n"
  printf "\n"

  printf "%s in=[path/to/file] out=[path/to/file] conf=[section] ...\n" "${script_name}"
  printf "  --help, -h: Display this help"
  printf "  --trace   : Trace script"
  printf "  <in>      : Mandatory input file (path absolue or relative to %s)\n" "$PWD"
  printf "  <out>     : [optional] output file (path absolue or relative to %s)\n" "$PWD"
  printf "  <conf>    : Mandatory section to fill as following detailled.\n"
  usage_setup
  usage_tee
  usage_seco
  usage_ele
  printf "\n"

  exit 1
}

usage_setup()
{
  printf "\n"
  printf "General SMW configuration settings\n"
  printf "  conf=setup smw_config_file=[path/to/file] database=[path/to/file]\n"
  printf "  <smw_config_file> : SMW library configuration file with absolute path\n"
  printf "  <database>        : SMW library database file with absolute path\n"
  printf "\n"
  printf "Device specific SMW configuration settings. Overwrite the general configuration.\n"
  printf "  conf=setup-<device> smw_config_file=[path/to/file] database=[path/to/file]\n"
  printf "  <device>          : Platform hostname or start of the hostname (e.g. imx8ulp)\n"
  printf "  <smw_config_file> : SMW library configuration file with absolute path\n"
  printf "  <database>        : SMW library database file with absolute path\n"

}

usage_tee()
{
  printf "\n"
  printf "  conf=tee ta_uuid=[uuid]\n"
  printf "  <ta_uuid> : UUID value (e.g. 11b5c4aa-6d20-11ea-bc55-0242ac130003)\n"
}

usage_seco()
{
  printf "\n"
  printf "  conf=seco id=[storage id] nonce=[storage nonce] replay=[max]\n"
  printf "  <id>     : Storage identifier 32 bits integer (e.g. 0x534d5754)\n"
  printf "  <nonce>  : Storage nonce 32 bits integer (e.g 0x444546)\n"
  printf "  <replay> : Storage maximum rollback protection count 16 bits integer (e.g. 1000)\n"
}

usage_ele()
{
  printf "\n"
  printf "  conf=ele id=[storage id] nonce=[storage nonce]\n"
  printf "  <id>     : Storage identifier 32 bits integer (e.g. 0x534d5754)\n"
  printf "  <nonce>  : Storage nonce 32 bits integer (e.g 0x444546)\n"
}

opt_infile=
opt_outfile=
opt_section=
opt_id=
opt_nonce=
opt_replay=
opt_ta_uuid=
opt_smw_config_file=
opt_database=

for arg in "$@"
do
  case ${arg} in
      --help|-h)
        usage
        ;;

      --trace)
        set -x
        ;;

      in=*)
        opt_infile="${arg#*=}"
       ;;

      out=*)
        opt_outfile="${arg#*=}"
        ;;

      conf=*)
        opt_section="${arg#*=}"
        opt_section=$(echo "${opt_section}" | sed -e "s/.*/\L&/")
        ;;

      id=*)
        opt_id="${arg#*=}"
        ;;

      nonce=*)
        opt_nonce="${arg#*=}"
        ;;

      replay=*)
        opt_replay="${arg#*=}"
        ;;

      ta_uuid=*)
        opt_ta_uuid="${arg#*=}"
        ;;

      smw_config_file=*)
        opt_smw_config_file="${arg#*=}"
        ;;

      database=*)
        opt_database="${arg#*=}"
        ;;
  esac
  shift
done

if [ -z "${opt_infile}" ]; then
  usage
fi

if [ -z "${opt_outfile}" ]; then
  opt_outfile="${opt_infile}"
else
  eval 'mkdir -p $(dirname "${opt_outfile}")'
  eval 'cp ${opt_infile} ${opt_outfile}'
fi

opt_outfile=$(realpath "${opt_outfile}")

case ${opt_section} in
  setup*)
    if [ -z "${opt_smw_config_file}" ] && [ -z "${opt_database}" ]; then
      usage_setup
    fi

    if [ -n "${opt_smw_config_file}" ]; then
      set_conf_entry "${opt_outfile}" "${opt_section}" \
                     "smw_config_file" "${opt_smw_config_file}"
    fi

    if [ -n "${opt_database}" ]; then
      set_conf_entry "${opt_outfile}" "${opt_section}" \
                     "database" "${opt_database}"
    fi
    ;;

  tee)
    if [ -z "${opt_ta_uuid}" ]; then
      usage_tee
    fi

    set_conf_entry "${opt_outfile}" "${opt_section}" \
                   "ta_uuid" "${opt_ta_uuid}"
    ;;

  seco)
    if [ -z "${opt_id}" ] || [ -z "${opt_nonce}" ] || [ -z "${opt_replay}" ]; then
      usage_seco
    fi
    set_conf_entry "${opt_outfile}" "${opt_section}" \
                   "id" "${opt_id}"
    set_conf_entry "${opt_outfile}" "${opt_section}" \
                   "nonce" "${opt_nonce}"
    set_conf_entry "${opt_outfile}" "${opt_section}" \
                   "replay" "${opt_replay}"
    ;;

  ele)
    if [ -z "${opt_id}" ] || [ -z "${opt_nonce}" ]; then
      usage_ele
    fi
    set_conf_entry "${opt_outfile}" "${opt_section}" \
                   "id" "${opt_id}"
    set_conf_entry "${opt_outfile}" "${opt_section}" \
                   "nonce" "${opt_nonce}"
    ;;

  *)
    usage
    ;;
esac