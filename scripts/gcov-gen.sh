#!/bin/bash
set -eE
trap 'error ${LINENO}' ERR

#
# Copy gcno and gcda in the same temporary directory
# Generate the analyze data file
# Generate the html report
#

# Definition of the tools name
lcov_tool="lcov"
gcov_tool="gcov"
genhtml_tool="genhtml"

lcov_git="https://github.com/linux-test-project/lcov.git"

script_name=$0
opt_gcno_dir=
opt_gcda_dir=
opt_merge_dir=
opt_merge=1
out_dir="code-coverage"
config_rc=""
opt_lcov=
opt_html=
opt_gcov_path=
opt_lcov_path=
opt_lcov_ver="1.15"
git_toplevel=

#
# Return function value (because of set -e trapping)
# 1 = ok
# 0 = error
ret_func=0

# Get the Git Top level directory
function get_toplevel() {
    local topdir
    topdir=$(git rev-parse --show-toplevel)
    echo "$topdir"
}

function usage_install()
{
    git_toplevel=$(get_toplevel)

    printf "\n"
    printf "To install the lcov tools\n"
    printf " %s install lcov=<path> lcov_ver=<ver>\n" "${script_name}"
    printf "\n"
    printf "  Install lcov tool from git repo %s\n" "lcov_git"
    printf "    lcov=     Full path where to install "
    printf "(default %s/.tmp)\n" "${git_toplevel}"
    printf "    lcov_ver= LCOV minimal version (default %s)\n" "${opt_lcov_ver}"
    printf "\n"
}

function usage_report()
{
    printf "\n"
    printf "To generate code coverage report\n"
    printf " %s report gcno=<path> gcda=<path> src=<path> [options]\n" "${script_name}"
    printf "\n"
    printf "  Merge gcov data files gcno and gcda in temporary directory\n"
    printf "  Generate the lcov report in HTML format\n"
    printf "\n"
    printf "  Mandatory"
    printf "    gcno=   Base directory where the *.gcno files are\n"
    printf "    gcda=   Base directory where the *.gcda files are\n"
    printf "    src=    Base directory where the source (*.h, *.c) files are\n"
    printf "\n"
    printf "  Misc:\n"
    printf "    help    Print this help\n"
    printf "\n"
    printf "  Options:\n"
    printf "    nomerge   If defined, gcno and gcda path must be the same"
    printf "              \"tmp\" option must not be defined if this option set\n"
    printf "              (default gcno and gcda are merger in \"tmp\" directory\n"
    printf "    tmp=      Temporary directory where to merge *.gcno *.gcda"
    printf "              (default ./tmp)\n"
    printf "              \"nomerge\" must not be set if this option set\n"
    printf "    title=    Title of the HTML report add \" \" around string"
    printf "              (e.g. \"string\")\n"
    printf "    out=      HMTL report output directory\n"
    printf "    conf=     HMTL configuration file (*.rc)\n"
    printf "    gcov=     Full path and name of the gcov tool\n"
    printf "    lcov=     Full path to lcov tools (lcov/genhtml)\n"
    printf "    lcov_ver= LCOV minimal version (default %s)\n" "${opt_lcov_ver}"
    printf "\n"
}

function usage()
{
    printf "\n"
    printf "*****************************************\n"
    printf " Usage of Code Coverage GCOV/LCOV script \n"
    printf "*****************************************\n"
    usage_install
    usage_report

    exit 1
}


function parse_param()
{
    opt_mandatory=0
    exp_mandatory=3

    if [[ ${opt_action} == "install" ]]; then
        exp_mandatory=0
    fi

    for arg in "$@"
    do
        case ${arg} in
            help)
                usage
                ;;
            gcno=*)
                opt_gcno_dir="${arg#*=}"
                opt_mandatory=$((opt_mandatory + 1))
                ;;
            gcda=*)
                opt_gcda_dir="${arg#*=}"
                opt_mandatory=$((opt_mandatory + 1))
                ;;
            src=*)
                opt_mandatory=$((opt_mandatory + 1))
                opt_lcov="${opt_lcov} -b ${arg#*=}"
                ;;
            tmp=*)
                opt_merge_dir="${arg#*=}"
                if [[ ${opt_merge} -eq 0 ]]; then
                    usage
                fi
                ;;
            nomerge)
                opt_merge=0
                if [[ ! -z ${opt_merge_dir} ]]; then
                    usage
                fi
                ;;
            title=*)
                opt_html="${opt_html} -t \"${arg#*=}\""
                ;;
            out=*)
                out_dir="${arg#*=}"
                ;;
            conf=*)
                config_rc="${arg#*=}"
                opt_html="${opt_html} --config-file ${config_rc}"
                ;;
            gcov=*)
                opt_gcov_path="${arg#*=}"
                ;;
            lcov=*)
                opt_lcov_path="${arg#*=}"
                ;;
            lcov_ver=*)
                opt_lcov_ver="${arg#*=}"
                ;;
            *)
                echo "Invalid option: ${arg}"
                usage
                ;;
        esac
        shift
    done

    if [[ ${opt_mandatory} -lt ${exp_mandatory} ]]; then
        usage
    fi

}

function check_directory()
{
    declare -n mydir=$1
    mydir="${mydir/\~/$HOME}"

    if [[ ! -d "${mydir}" ]]; then
        printf "%s is not a directory\n" "${mydir}"
        ret_func=0
    else
        ret_func=1
    fi
}

function find_file()
{
    declare -n retfile=$1
    local dir=$2
    local found=""
    local tofind="${retfile}"
    local lists

    if [[ $# -eq 3 ]];  then
        tofind="$3""${tofind}"
    fi

    lists=$(find "${dir}" -type f -name "${tofind}" -print)
    for file in "${lists[@]}"
    do
        if [[ -f "${file}" ]]; then
            found="${file}"
            break
        fi
    done

    if [[ -z "${found}" ]]; then
        printf "%s not found in %s\n" "${tofind}" "${dir}"
        ret_func=0
    else
        retfile="${found}"
        ret_func=1
    fi
}

function install_lcov()
{
    local cur_path=$PWD

    if [[ -z "${opt_lcov_path}" ]]; then
        git_toplevel=$(get_toplevel)
        opt_lcov_path="${git_toplevel}/.tmp"
    fi

    check_lcov_tools
    if [[ ${ret_func} -eq 1 ]]; then
        printf "LCOV tool already installed\n"
        return
    fi

    printf "Installation of lcov in %s\n" "${opt_lcov_path}"

    # Get lcov from git and set to requested tag version
    eval "mkdir -p ${opt_lcov_path}"
    eval "cd ${opt_lcov_path}"
    if [[ -d "lcov" ]]; then
        printf "Directory already exist. Please check.\n"
        exit 1
    fi

    eval "git clone ${lcov_git}"
    eval "cd ${opt_lcov_path}/lcov"
    eval "git checkout v${opt_lcov_ver}"

    eval "cd ${cur_path}"
    find_file lcov_tool "${opt_lcov_path}"
    if [[ ${ret_func} -eq 0 ]]; then exit 1; fi
    find_file genhtml_tool "${opt_lcov_path}"
    if [[ ${ret_func} -eq 0 ]]; then exit 1; fi
}

function check_lcov_version()
{
    #
    # Check if lcov is installed and version is v1.15 minimum
    #
    if ! hash ${lcov_tool} 2>/dev/null; then
        printf "lcov not installed\n"
        install_lcov
    fi

    # Get the current lcov version installed
    lcov_ver=$(${lcov_tool} -ver 2>&1 | grep -Eo "LCOV version [0-9]\.[0-9]+")
    lcov_ver=$(echo "${lcov_ver}" | grep -Eo '[0-9]\.[0-9]+')

    IFS='.' read -ra alcov_ver <<< "${lcov_ver}"
    IFS='.' read -ra aexp_ver <<< "${opt_lcov_ver}"

    match=${#aexp_ver[@]}
    if [[ ${#alcov_ver[@]} -eq ${#aexp_ver[@]} ]]; then
        for (( i=0; i<=match; i++ )); do
            if [[ ${alcov_ver[$i]} -lt ${aexp_ver[$i]} ]]; then
                break;
            fi
            match=$((match-1))
        done
    fi

    if [[ ${match} -ne 0 ]]; then
        printf "Bad version got %s expected %s\n" "${lcov_ver}" "${opt_lcov_ver}"
        ret_func=0
    else
        ret_func=1
    fi
}

function check_lcov_tools()
{
    if [[ ! -z "${opt_lcov_path}" ]]; then
        check_directory opt_lcov_path
        if [[ ${ret_func} -eq 0 ]]; then return; fi

        find_file lcov_tool "${opt_lcov_path}"
        if [[ ${ret_func} -eq 0 ]]; then return; fi
        find_file genhtml_tool "${opt_lcov_path}"
        if [[ ${ret_func} -eq 0 ]]; then return; fi
    fi

    check_lcov_version
}

function check_gcov_tools()
{
    if [[ ! -z "${opt_gcov_path}" ]]; then
        check_directory opt_gcov_path
        if [[ ${ret_func} -eq 0 ]]; then exit 1; fi

        find_file gcov_tool "${opt_gcov_path}" "*"
        if [[ ${ret_func} -eq 1 ]]; then
            opt_html="${opt_html} --rc geninfo_gcov_tool=${gcov_tool}"
        fi
    fi
}

function copy_file()
{
    eval "cp -R $1 $2"
}

function lcov_generate()
{
    eval "${lcov_tool} --gcov-tool ${gcov_tool} -c ${opt_lcov} \
           -d ${opt_merge_dir} -o code_cover.info"
}

function html_generate()
{
    if [[ -d "${out_dir}" ]]; then
        eval "rm -rf ${out_dir}"
    fi

    eval "${genhtml_tool} ${opt_html} --output-directory ${out_dir} \
          \"code_cover.info\""
}

function tar_report()
{
    printf "\n"
    printf "TAR report\n"
    eval "tar -cvzf ${out_dir}.tar.gz ${out_dir}"
}

function merge_gcda_gcno()
{
    # Set default merge dir if not defined
    if [[ -z ${opt_merge_dir} ]]; then
        opt_merge_dir="tmp"
    fi

    # Make the temporary directory
    if [[ -d "${opt_merge_dir}" ]]; then
        eval "rm -rf ${opt_merge_dir}"
    fi

    eval "mkdir -p ${opt_merge_dir}"

    #
    # Copy *.gcno to temporary directory
    copy_file "${opt_gcno_dir}" "${opt_merge_dir}"

    #
    # Copy *.gcda to temporary directory
    copy_file "${opt_gcda_dir}" "${opt_merge_dir}"
}

function check_gcda_gcno()
{
    if [[ "${opt_gcda_dir}" != "${opt_gcno_dir}" ]]; then
        usage
    fi

    opt_merge_dir=${opt_gcda_dir}
    check_directory opt_merge_dir
    if [[ ${ret_func} -eq 0 ]]; then exit 1; fi
}

function generate_report()
{
    #
    # Check if lcov tools are installed or present
    # in given lcov path option
    #
    check_lcov_tools
    if [[ ${ret_func} -eq 0 ]]; then exit 1; fi

    #
    # Check if gcov tools are installed or present
    # in given gcov path option
    #
    check_gcov_tools

    if [[ ${opt_merge} -eq 1 ]]; then
        merge_gcda_gcno
    else
        check_gcda_gcno
    fi

    #
    # Generate data coverage info file
    lcov_generate

    #
    # Generate HTML report file
    html_generate

    #
    # Tar report
    tar_report

    if [[ ${opt_merge} -eq 1 ]]; then
        if [[ -d "${opt_merge_dir}" ]]; then
            eval "rm -rf ${opt_merge_dir}"
        fi
    fi

    if [[ -e "code_cover.info" ]]; then
        eval "rm code_cover.info"
    fi
}

if [[ $# -eq 0 ]]; then
    usage
fi

opt_action="$1"
shift

parse_param "$@"

case ${opt_action} in
    install)
        install_lcov
        ;;

    report)
        generate_report
        ;;

    *)
        printf "Unknown action %s\n" "$1"
        usage
        ;;
esac
