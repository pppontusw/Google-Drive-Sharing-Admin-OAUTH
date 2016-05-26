$('.showrefresh').click(function() {
	$('.hidden-refreshing').removeClass('hidden');
});

var options = {
  valueNames: [ 'name', 'mail' ]
};

var itemOptions = {
	valueNames: [ 'name' ]
};

var userList = new List('users', options);
var itemList = new List('items', itemOptions);