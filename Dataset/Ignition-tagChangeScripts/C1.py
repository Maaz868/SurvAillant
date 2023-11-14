def valueChanged(tag, tagPath, previousValue, currentValue, initialChange, missedEvents):
#	system.tag.write('[default]CloseLoad1', False)
	current_value = currentValue.value
	lower_boundary = 2000
	upper_boundary = 3000
				
	if current_value < lower_boundary or current_value > upper_boundary:
	    system.tag.write('[default]CloseLoad1', True)
				