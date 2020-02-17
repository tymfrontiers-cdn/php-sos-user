<?php
namespace SOS;
use \TymFrontiers\InstanceError,
    \TymFrontiers\Validator,
    \TymFrontiers\Data;

class User{
  use \TymFrontiers\Helper\MySQLDatabaseObject,
      \TymFrontiers\Helper\Pagination,
      UserProfile;

  protected static $_primary_key='_id';
  protected static $_db_name = MYSQL_BASE_DB;
  protected static $_table_name = "user";
	protected static $_db_fields = [
    "_id",
    "status",
    "email",
    "phone",
    "password",
    "_created"
  ];
  protected static $_prop_type = [];
  protected static $_prop_size = [];

  const PREFIX = "USR.";
  const SURFIX = ".USR";

  protected $_id;
  public $status="PENDING";
  public $email;
  public $phone;
  public $password;

  protected $_created;

  public $errors = [];

  function __construct($user=""){
    $this->init($user);
  }

  public function init($user){
    return \is_array($user) ? $this->_createNew($user) : (
      (new Validator() )->username($user,["user","username",3,12])
      ? $this->_objtize($user) : false
    );
  }

  public static function authenticate(string $email, string $password,string $country_code="NG"){
    global $database, $access_ranks;
    if (!$database instanceof \TymFrontiers\MySQLDatabase) {
      throw new \Exception("Database not set: '\$database' not instance \TymFrontiers\MySQLDatabase", 1);
    }
    $data = new Data();
    $whost = WHOST;
    $data_db = MYSQL_DATA_DB;
    $email = $database->escapeValue($email);
    $password = $database->escapeValue($password);
    $sql = "SELECT u._id, u.password
            FROM :db:.:tbl: AS u
            WHERE u.status IN('ACTIVE','PENDING') ";
    if ( \filter_var($email, FILTER_VALIDATE_EMAIL) ) {
      $sql .= " AND u.email = '{$email}' ";
    } else if (@ $number = $data->phoneToIntl($email,$country_code)) {
      $sql .= " AND u.phone = '{$number}' ";
    } else {
      return false;
    }
    $sql .= " LIMIT 1";
    $result_array = self::findBySql($sql);
    $record = !empty($result_array) ? $data->pwdCheck($password,$result_array[0]->password) : false;
    if( $record && ($user = self::find($result_array[0]->_id,"id")) ){
      $user = $user[0];
      $usr = new \StdClass();
      $user->avatar = $user->avatar;
      $usr->id = $usr->uniqueid = $user->id;
      $usr->access_group = "USER";
      $usr->access_rank = (
          \is_array($access_ranks) && \array_key_exists($usr->access_group,$access_ranks)
        ) ? $access_ranks[$usr->access_group]
          : 0;
      $usr->name = $user->name;
      $usr->surname = $user->surname;
      $usr->email = $user->email;
      $usr->phone = $user->phone;
      $usr->status = $user->status;
      $usr->avatar = $user->avatar;
      $usr->country_code = $user->country_code;
      return $usr;
    }
    return false;
  }
  public function isActive(bool $strict = false){
    if( $strict ){
      return !empty($this->_id) && \in_array($this->status,['ACTIVE']);
    }else{
      return !empty($this->_id) && \in_array($this->status,['ACTIVE','PENDING']);
    }
    return false;
  }
  private function _createNew(array $user){
    global $database;
    $data = new Data();
    if( \is_array($user) ){
      if (
        empty($user['email'])
        || empty($user['name'])
        || empty($user['surname'])
        || empty($user['country_code'])
      ) {
        $this->errors["_createNew"][] = [
          @$GLOBALS['access_ranks']['DEVELOPER'],
          256,
          "Required properties [email, name, surname, country_code] not set", __FILE__,
          __LINE__
        ];
        return false;
      }
      foreach($user as $key=>$val){
        if( \property_exists(__CLASS__, $key) && !empty($val) ){
          $this->$key = $val;
        }
      }
      $this->_id = \strftime("%y%m%d",\time()) . $data->uniqueRand("", 6, $data::RAND_NUMBERS);
      $this->password = $data->pwdHash($this->password);
      // get user connection
      if ( $database->getUser() !== MYSQL_USER_USERNAME ) {
        // open new db connection
        $conn = new \TymFrontiers\MySQLDatabase(MYSQL_SERVER, MYSQL_USER_USERNAME, MYSQL_USER_PASS, self::$_db_name);
      } else {
        $conn =& $database;
      }
      if( $this->_create($conn) ){
        $this->password = null;
        return $this->_createProfile($this->_id, $user, $conn);
      }else{
        $this->_id = null;
        $this->errors['self'][] = [0,256, "Request failed at this this tym.",__FILE__, __LINE__];
        if( \class_exists('\TymFrontiers\InstanceError') ){
          $ex_errors = new \TymFrontiers\InstanceError($conn);
          if( !empty($ex_errors->errors) ){
            foreach( $ex_errors->get("",true) as $key=>$errs ){
              foreach($errs as $err){
                $this->errors['self'][] = [0,256, $err,__FILE__, __LINE__];
              }
            }
          }
        }
      }
    }
    return false;
  }
  private function _objtize(string $id){
    if ($found = self::find($id)) {
      foreach ($found[0] as $prop=>$val) {
        if (!\in_array($prop,["password"])) $this->$prop = $val;
      }
      return true;
    }
    return false;
  }
  public function id () { return $this->_id; }

}
